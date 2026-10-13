"""End-to-end: record the demo app, analyze, verify, refresh, generate and use clients."""

import importlib.util
import json
import shutil
import subprocess
import sys
import time

import pytest
from conftest import record

from dapi.analysis import analyze
from dapi.service import DapiService
from dapi.session import resolve_session

DEMO_SECRETS = ("demo-password", "eyJ")


def _ep(svc, method, path):
    return next(
        e for e in svc.endpoints_discover()["endpoints"] if e["method"] == method and e["path"] == path
    )


def assert_no_secrets(obj):
    text = json.dumps(obj)
    for s in DEMO_SECRETS:
        assert s not in text, f"secret material {s!r} leaked into tool output"


def test_catalog_and_auth_model(recorded):
    ws, base = recorded
    svc = DapiService(ws)
    eps = svc.endpoints_discover()
    assert_no_secrets(eps)
    paths = {(e["method"], e["path"]) for e in eps["endpoints"]}
    assert ("GET", "/api/v1/projects/{project_id}") in paths
    assert ("GET", "/api/v1/projects/{project_id}/tasks") in paths
    assert ("POST", "/api/v1/projects/{project_id}/tasks") in paths
    assert _ep(svc, "GET", "/api/v1/me")["auth"] == "yes"
    assert _ep(svc, "GET", "/api/v1/public/health")["auth"] == "no"
    assert _ep(svc, "POST", "/api/v1/auth/login")["tags"] == ["login"]

    auth = svc.auth_analyze(base)
    assert_no_secrets(auth)
    bearer = next(m for m in auth["mechanisms"] if m["type"] == "bearer")
    assert bearer["issued_by"][0]["location"] == "body:$.access_token"
    assert bearer["issued_by"][0]["endpoint"].endswith("/api/v1/auth/login")
    assert bearer["lifetime_seconds"] == 300
    login = auth["login"][0]
    assert login["fields"] == {"body:$.username": "username", "body:$.password": "password"}
    assert "set-cookie:sid" in login["issues"]


def test_dependencies(recorded):
    ws, _ = recorded
    deps = DapiService(ws).dependencies_discover()
    data_edges = [e for e in deps["edges"] if e["type"] == "data"]
    assert any(
        e["from_endpoint"] == "GET /api/v1/projects"
        and e["from_field"] == "$.items[].id"
        and e["to_field"] == "path:project_id"
        for e in data_edges
    )
    assert "GET /api/v1/projects" in deps["prerequisites"]["GET /api/v1/projects/{project_id}"]
    order = deps["call_order"]
    assert order.index("POST /api/v1/auth/login") < order.index("GET /api/v1/projects")


def test_session_verify_probe_and_ablation(recorded):
    ws, _ = recorded
    svc = DapiService(ws)
    report = svc.session_verify(probe_auth=True)
    assert_no_secrets(report)
    assert report["valid"] is True
    assert all(r["ok"] and r["schema_matches"] for r in report["checked"])
    assert all(r["unauthenticated_probe"]["auth_required"] for r in report["checked"])
    assert report["credential_ablation"]["necessary"] == {"header:authorization": True, "cookie:sid": False}
    # probes become evidence: every verified endpoint now has a confirmed requirement
    for r in report["checked"]:
        assert svc.endpoint_get(r["endpoint_id"])["auth"]["required"] == "yes"
    mech = {m["location"]: m for m in svc.auth_analyze()["mechanisms"]}
    assert mech["cookie:sid"]["necessary"] is False


def test_verify_refuses_unsafe_endpoints(recorded):
    ws, _ = recorded
    svc = DapiService(ws)
    post = _ep(svc, "POST", "/api/v1/projects/{project_id}/tasks")
    report = svc.session_verify(endpoint_ids=[post["id"]])
    assert report["rejected"][0]["reason"].startswith("not read-only")
    before = ws.store.flow_count()
    assert ws.store.flow_count() == before  # nothing was sent


def test_expired_token_is_refreshed_automatically(ws, short_ttl_demo):
    record(ws, short_ttl_demo, expire_wait=2.5)
    auth = DapiService(ws).auth_analyze()
    assert auth["refresh"][0]["rotates_refresh_token"] is True
    assert auth["reactive_refreshes"], "401 -> refresh pattern should be detected"
    time.sleep(2.2)  # let the captured access token expire
    report = DapiService(ws).session_verify()
    assert report["refresh"]["refreshed"] is True
    assert report["valid"] is True
    # the refreshed (rotated) refresh token works again: lineage tracking picks the newest one
    time.sleep(2.2)
    again = DapiService(ws).session_refresh()
    assert again["refreshed"] is True, again


def test_login_replay_requires_opt_in(ws, demo):
    record(ws, demo)  # no token expiry in this capture, so no refresh flow was observed
    svc = DapiService(ws)
    no = svc.session_refresh(allow_login=False)
    assert no["refreshed"] is False and "allow_login" in no["reason"]
    before = ws.store.flow_count()
    assert ws.store.flow_count() == before
    yes = svc.session_refresh(allow_login=True)
    assert yes["refreshed"] and yes["method"] == "login"
    assert "body:$.access_token" in yes["new_credentials"]
    assert_no_secrets(yes)


def _load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = mod
    spec.loader.exec_module(mod)
    return mod


def test_generated_python_client(recorded, tmp_path):
    ws, base = recorded
    res = DapiService(ws).client_generate(language="python", output_dir=str(tmp_path / "gen"))
    assert_no_secrets(res)
    source = open(res["path"]).read()
    for s in ("demo-password", "eyJ", "rt_"):
        assert s not in source, "generated code must not embed credentials"
    compile(source, res["path"], "exec")
    mod = _load_module(tmp_path / "gen" / "local_api_client.py")
    client = mod.LocalApiClient(base, username="demo", password="demo-password")
    client.login()
    assert client.get_me()["id"] == 7
    projects = client.list_projects()["items"]
    assert {p["name"] for p in projects} == {"Apollo", "Gemini", "Mercury"}
    assert client.get_project(101)["name"] == "Apollo"
    assert client.create_project_task(101, {"title": "from test"})["title"] == "from test"
    assert client.get_public_health()["status"] == "ok"
    with pytest.raises(mod.ApiError) as err:
        client.get_project(999)
    assert err.value.status_code == 404
    # no manual login: reuse the captured session
    fresh = mod.LocalApiClient.from_dapi(str(ws.home), base_url=base)
    assert fresh.get_me()["name"] == "Demo User"


def test_generated_client_refreshes_on_401(ws, short_ttl_demo, tmp_path):
    record(ws, short_ttl_demo, expire_wait=2.5)
    res = DapiService(ws).client_generate(
        language="python", output_dir=str(tmp_path / "gen2"), class_name="Demo"
    )
    mod = _load_module(tmp_path / "gen2" / "local_api_client.py")
    client = mod.Demo(short_ttl_demo, username="demo", password="demo-password", auto_refresh=True)
    client.login()
    client.token_expires_at = None  # disable proactive refresh to exercise the reactive 401 path
    time.sleep(2.3)
    assert client.get_me()["id"] == 7
    assert res["auth"]["refresh"].endswith("/api/v1/auth/refresh")


@pytest.mark.skipif(not shutil.which("node") or not shutil.which("tsc"), reason="node/tsc not installed")
def test_generated_typescript_client(recorded, tmp_path):
    ws, base = recorded
    out = tmp_path / "ts"
    res = DapiService(ws).client_generate(language="typescript", output_dir=str(out))
    ts = out / "local_api_client.ts"
    assert "demo-password" not in ts.read_text()
    (out / "main.ts").write_text(
        "import { LocalApiClient } from './local_api_client';\n"
        "(async () => {\n"
        f"  const c = new LocalApiClient({{ baseUrl: {json.dumps(base)}, username: 'demo', password: 'demo-password' }});\n"
        "  await c.login();\n"
        "  const me = await c.getMe();\n"
        "  const tasks = await c.listProjectTasks(101, { status: 'open' });\n"
        "  const created = await c.createProjectTask(102, { title: 'ts' });\n"
        "  console.log(JSON.stringify({ id: me.id, tasks: tasks.length, created: created.title }));\n"
        "})().catch((e) => { console.error(e); process.exit(1); });\n"
    )
    tsc = subprocess.run(
        [
            "tsc",
            "--strict",
            "--target",
            "es2022",
            "--module",
            "commonjs",
            "--lib",
            "es2022,dom",
            "--types",
            "node",
            "--skipLibCheck",
            "--outDir",
            str(out / "dist"),
            str(out / "main.ts"),
        ],
        capture_output=True,
        text=True,
    )
    if "Cannot find type definition file for 'node'" in tsc.stdout:
        (out / "main.ts").write_text("declare const process: any;\n" + (out / "main.ts").read_text())
        tsc = subprocess.run(
            [
                "tsc",
                "--strict",
                "--target",
                "es2022",
                "--module",
                "commonjs",
                "--lib",
                "es2022,dom",
                "--skipLibCheck",
                "--outDir",
                str(out / "dist"),
                str(out / "main.ts"),
            ],
            capture_output=True,
            text=True,
        )
    assert tsc.returncode == 0, tsc.stdout + tsc.stderr
    run = subprocess.run(["node", str(out / "dist" / "main.js")], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    out_data = json.loads(run.stdout)
    assert out_data["id"] == 7 and out_data["tasks"] >= 1 and out_data["created"] == "ts"
    assert res["class_name"] == "LocalApiClient"


def test_docs_generation(recorded, tmp_path):
    ws, base = recorded
    svc = DapiService(ws)
    res = svc.docs_generate(format="openapi", output_path=str(tmp_path / "openapi.json"))
    doc = json.loads(open(res["path"]).read())
    assert doc["openapi"] == "3.1.0"
    assert doc["components"]["securitySchemes"]["observedAuth"] == {"type": "http", "scheme": "bearer"}
    op = doc["paths"]["/api/v1/projects/{project_id}"]["get"]
    assert op["x-dapi-evidence-flows"] and op["parameters"][0]["name"] == "project_id"
    md = svc.docs_generate(format="markdown", output_path=str(tmp_path / "API.md"))
    text = open(md["path"]).read()
    assert "## Authentication" in text and "/api/v1/projects/{project_id}" in text
    assert "demo-password" not in text


def test_resolve_session_is_for_programs_only(recorded):
    ws, base = recorded
    sess = resolve_session(ws, base)
    assert sess["headers"]["authorization"].startswith("Bearer eyJ")
    shown = DapiService(ws).traffic_get(4)
    assert_no_secrets(shown)


def test_traffic_tools(recorded):
    ws, _ = recorded
    svc = DapiService(ws)
    listing = svc.traffic_list(method="GET", path_contains="/projects")
    assert listing["total"] >= 4
    detail = svc.traffic_get(3)
    assert detail["request"]["body"]["password"].startswith("{{secret:")
    assert {s["kind"] for s in detail["secrets"]} >= {"username", "password", "access_token", "refresh_token"}
    hits = svc.traffic_search("Apollo")
    assert hits["hits"]
    assert_no_secrets([listing, detail, hits, svc.credentials_list(), svc.status()])


def test_analysis_is_cached_until_new_flows(recorded):
    ws, base = recorded
    a1 = analyze(ws)
    assert analyze(ws) is a1
    record(ws, base)
    assert analyze(ws) is not a1
