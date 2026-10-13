"""GraphQL: per-operation cataloging, auth detection on errors-only 200s, verification and codegen."""

import importlib.util
import json
import shutil
import subprocess
import sys

import httpx
import pytest
from scenario import run_graphql_session

from dapi.capture.httpx_recorder import RecordingTransport
from dapi.service import DapiService


@pytest.fixture
def gql_recorded(ws, demo):
    with httpx.Client(transport=RecordingTransport(ws)) as client:
        run_graphql_session(client, demo)
    return ws, demo


def _ops(svc):
    return {e.get("graphql"): e for e in svc.endpoints_discover()["endpoints"] if e.get("graphql")}


def test_operations_are_separate_endpoints(gql_recorded):
    ws, _ = gql_recorded
    svc = DapiService(ws)
    ops = _ops(svc)
    assert set(ops) == {"query Viewer", "query Project", "mutation CreateTask"}
    assert ops["query Viewer"]["read_only"] and ops["query Project"]["read_only"]
    assert not ops["mutation CreateTask"]["read_only"]
    # the unauthenticated Viewer call returned 200 with an UNAUTHENTICATED error: that proves auth is required
    assert ops["query Viewer"]["auth"] == "yes"
    project = svc.endpoint_get(ops["query Project"]["id"])
    assert project["request_schema"]["properties"] == {"id": {"type": "integer"}}
    data = project["responses"]["200"]["schema"]["properties"]["data"]["properties"]["project"]
    assert "tasks" in data["properties"]
    assert project["graphql"]["document"].startswith("query Project")


def test_verify_uses_graphql_queries(gql_recorded):
    ws, _ = gql_recorded
    report = DapiService(ws).session_verify(probe_auth=True, max_endpoints=5)
    checked = {c["endpoint"]: c for c in report["checked"]}
    viewer = next(c for name, c in checked.items() if "query Viewer" in name)
    assert viewer["ok"] and viewer["unauthenticated_probe"]["auth_required"] is True
    assert not any("CreateTask" in name for name in checked), "mutations are never sent during verification"
    assert report["valid"]


def test_openapi_has_one_entry_per_operation(gql_recorded, tmp_path):
    ws, _ = gql_recorded
    res = DapiService(ws).docs_generate(output_path=str(tmp_path / "o.json"))
    paths = json.loads(open(res["path"]).read())["paths"]
    assert {"/api/graphql#Viewer", "/api/graphql#Project", "/api/graphql#CreateTask"} <= set(paths)


def test_generated_python_graphql_methods(gql_recorded, tmp_path):
    ws, base = gql_recorded
    res = DapiService(ws).client_generate(output_dir=str(tmp_path))
    names = {m["name"] for m in res["methods"]}
    assert {"viewer", "project", "create_task"} <= names
    spec = importlib.util.spec_from_file_location("gql_client", tmp_path / "local_api_client.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gql_client"] = mod
    spec.loader.exec_module(mod)
    anon = mod.LocalApiClient(base, auto_refresh=False)
    with pytest.raises(mod.GraphQLError):
        anon.viewer()
    client = mod.LocalApiClient(base, username="demo", password="demo-password")
    client.login()
    assert client.viewer()["data"]["viewer"]["name"] == "Demo User"
    assert client.project({"id": 102})["data"]["project"]["name"] == "Gemini"
    assert client.create_task({"projectId": 103, "title": "gen"})["data"]["createTask"]["title"] == "gen"
    # errors-only auth failure triggers re-login, then succeeds
    client.token = "expired"
    client.token_expires_at = None
    assert client.viewer()["data"]["viewer"]["id"] == 7


@pytest.mark.skipif(not shutil.which("node") or not shutil.which("tsc"), reason="node/tsc not installed")
def test_generated_typescript_graphql_methods(gql_recorded, tmp_path):
    ws, base = gql_recorded
    DapiService(ws).client_generate(language="typescript", output_dir=str(tmp_path))
    (tmp_path / "main.ts").write_text(
        "declare const process: any;\n"
        "import { LocalApiClient, GraphQLError } from './local_api_client';\n"
        "(async () => {\n"
        f"  let denied = false; try {{ await new LocalApiClient({{ baseUrl: {json.dumps(base)}, autoRefresh: false }}).viewer(); }} catch (e) {{ denied = e instanceof GraphQLError; }}\n"
        f"  const c = new LocalApiClient({{ baseUrl: {json.dumps(base)}, username: 'demo', password: 'demo-password' }});\n"
        "  await c.login();\n"
        "  const v = await c.viewer();\n"
        "  const p = await c.project({ id: 101 });\n"
        "  console.log(JSON.stringify({ denied, name: v.data.viewer.name, project: p.data.project.name }));\n"
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
            "--skipLibCheck",
            "--outDir",
            str(tmp_path / "dist"),
            str(tmp_path / "main.ts"),
        ],
        capture_output=True,
        text=True,
    )
    assert tsc.returncode == 0, tsc.stdout + tsc.stderr
    run = subprocess.run(
        ["node", str(tmp_path / "dist" / "main.js")], capture_output=True, text=True, timeout=30
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout) == {"denied": True, "name": "Demo User", "project": "Apollo"}
