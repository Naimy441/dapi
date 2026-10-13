"""Cookie-session + CSRF web app (Django style): analysis, verification and generated clients."""

import importlib.util
import json
import shutil
import subprocess
import sys

import pytest

from dapi.service import DapiService

SECRETS = ("wonderland",)


def _no_secrets(obj):
    text = json.dumps(obj)
    assert not any(s in text for s in SECRETS)


def test_auth_model(web_recorded):
    ws, _ = web_recorded
    auth = DapiService(ws).auth_analyze()
    _no_secrets(auth)
    login = auth["login"][0]
    assert (
        login["endpoint"].endswith("POST " + login["endpoint"].split("POST ")[1])
        and "/login" in login["endpoint"]
    )
    assert login["fields"]["form:password"] == "password" and login["fields"]["form:username"] == "username"
    assert "set-cookie:sessionid" in login["issues"]
    assert auth["csrf"] == [{"header": "x-csrftoken", "source": "set-cookie:csrftoken"}]
    issuers = {m["location"]: m["issued_by"][0]["endpoint"] for m in auth["mechanisms"]}
    assert issuers["cookie:sessionid"].endswith("POST " + issuers["cookie:sessionid"].split("POST ")[1])
    assert issuers["cookie:csrftoken"].split(" ")[0] == "GET"


def test_verify_and_ablation(web_recorded):
    ws, _ = web_recorded
    report = DapiService(ws).session_verify(probe_auth=True)
    _no_secrets(report)
    assert report["valid"]
    necessary = report["credential_ablation"]["necessary"]
    assert necessary["cookie:sessionid"] is True
    assert necessary["cookie:csrftoken"] is False


def test_login_replay_with_csrf(web_recorded):
    ws, _ = web_recorded
    svc = DapiService(ws)
    res = svc.session_refresh(allow_login=True)
    _no_secrets(res)
    assert res["refreshed"] and res["method"] == "login" and res["status"] == 302
    assert "set-cookie:sessionid" in res["new_credentials"]
    report = svc.session_verify()
    assert report["valid"]
    assert report["session"]["source"].startswith("observed flow")


def _load(path):
    spec = importlib.util.spec_from_file_location(path.stem + "_web", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_generated_python_client_handles_csrf_login(web_recorded, tmp_path):
    ws, base = web_recorded
    res = DapiService(ws).client_generate(output_dir=str(tmp_path))
    assert res["auth"]["kind"] == "cookie" and res["auth"]["cookies"] == ["sessionid"]
    source = open(res["path"]).read()
    assert "wonderland" not in source
    mod = _load(tmp_path / "local_api_client.py")
    assert mod.LOGIN_FLOW["prerequisites"][0]["values"] == {"csrfmiddlewaretoken": {"cookie": "csrftoken"}}
    assert mod.LOGIN_FLOW["secret_params"] == []
    client = mod.LocalApiClient(base, username="alice", password="wonderland")
    client.login()  # GET /login for a CSRF cookie, then the form POST
    assert client.get_api_profile()["name"] == "Alice"
    created = client.create_api_note({"title": "csrf ok", "body": "y"})  # needs X-CSRFToken echo
    assert created["title"] == "csrf ok"
    assert client.get_api_note(created["id"])["title"] == "csrf ok"
    with pytest.raises(RuntimeError):
        mod.LocalApiClient(base, username="alice", password="wrong").login()
    reused = mod.LocalApiClient.from_dapi(str(ws.home), base_url=base)
    assert reused.list_api_notes()[0]["id"] == 1


@pytest.mark.skipif(not shutil.which("node") or not shutil.which("tsc"), reason="node/tsc not installed")
def test_generated_typescript_client_handles_csrf_login(web_recorded, tmp_path):
    ws, base = web_recorded
    DapiService(ws).client_generate(language="typescript", output_dir=str(tmp_path))
    (tmp_path / "main.ts").write_text(
        "declare const process: any;\n"
        "import { LocalApiClient } from './local_api_client';\n"
        "(async () => {\n"
        f"  const c = new LocalApiClient({{ baseUrl: {json.dumps(base)}, username: 'alice', password: 'wonderland' }});\n"
        "  await c.login();\n"
        "  const me = await c.getApiProfile();\n"
        "  const note = await c.createApiNote({ title: 'ts', body: 'z' });\n"
        "  console.log(JSON.stringify({ name: me.name, title: note.title }));\n"
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
    assert json.loads(run.stdout) == {"name": "Alice", "title": "ts"}
