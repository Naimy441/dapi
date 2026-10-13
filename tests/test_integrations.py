"""Capture via a real mitmproxy process, HAR import, the MCP server over stdio, and the CLI."""

import json
import os
import socket
import subprocess
import sys

import anyio
import httpx
from conftest import raw_storage_bytes
from scenario import run_demo_session

from dapi import Workspace
from dapi.cli import main as cli_main
from dapi.service import DapiService

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE5MDAwMDAwMDAsImlhdCI6MTkwMDAwMDAwMH0.c2ln"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_mitmproxy_capture(ws, demo):
    svc = DapiService(ws)
    started = svc.capture_start(port=free_port(), scope=["127.0.0.1"])
    try:
        assert started["running"] and svc.status()["capture"]["running"]
        with httpx.Client(proxy=started["proxy_url"], timeout=10) as client:
            run_demo_session(client, demo)
    finally:
        stopped = svc.capture_stop()
    assert stopped["stopped"]
    flows = svc.traffic_list(limit=500)
    assert flows["total"] == 13
    assert {f["source"] for f in flows["flows"]} == {"mitmproxy"}
    eps = {(e["method"], e["path"]) for e in svc.endpoints_discover()["endpoints"]}
    assert ("GET", "/api/v1/projects/{project_id}/tasks") in eps
    ws.store._conn.execute("PRAGMA wal_checkpoint(FULL)")
    blob = raw_storage_bytes(ws)
    assert b"demo-password" not in blob and b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in blob
    log = (ws.home / "capture.log").read_text()
    assert "demo-password" not in log and "eyJ" not in log
    assert svc.session_verify()["valid"]


def make_har(path):
    def entry(
        method,
        url,
        status,
        req_headers=(),
        resp_headers=(),
        post=None,
        resp=None,
        t="2026-05-01T10:00:00.000Z",
    ):
        e = {
            "startedDateTime": t,
            "time": 12,
            "request": {
                "method": method,
                "url": url,
                "headers": [{"name": k, "value": v} for k, v in req_headers],
                "cookies": [],
            },
            "response": {
                "status": status,
                "headers": [{"name": k, "value": v} for k, v in resp_headers],
                "content": {
                    "mimeType": "application/json",
                    "text": json.dumps(resp) if resp is not None else "",
                },
            },
        }
        if post is not None:
            e["request"]["postData"] = {"mimeType": "application/x-www-form-urlencoded", "text": post}
        return e

    auth = [("authorization", "Bearer " + JWT)]
    har = {
        "log": {
            "version": "1.2",
            "entries": [
                entry(
                    "POST",
                    "https://shop.example.com/oauth/token",
                    200,
                    post="grant_type=password&username=ann&password=har-secret-pw",
                    resp={"access_token": JWT, "expires_in": 3600, "token_type": "bearer"},
                ),
                entry(
                    "GET",
                    "https://shop.example.com/v2/orders?limit=10",
                    200,
                    auth,
                    resp={"orders": [{"order_id": "ord_5f9d88b1c2", "total": 12.5}]},
                    t="2026-05-01T10:00:01.000Z",
                ),
                entry(
                    "GET",
                    "https://shop.example.com/v2/orders/ord_5f9d88b1c2",
                    200,
                    auth,
                    resp={"order_id": "ord_5f9d88b1c2", "total": 12.5, "items": []},
                    t="2026-05-01T10:00:02.000Z",
                ),
                entry(
                    "GET",
                    "https://shop.example.com/v2/orders/ord_5f9d88b1c2",
                    401,
                    resp={"error": "expired"},
                    t="2026-05-01T10:00:03.000Z",
                ),
                entry("GET", "https://cdn.example.com/logo.png", 200, t="2026-05-01T10:00:04.000Z"),
            ],
        }
    }
    path.write_text(json.dumps(har))


def test_har_import(ws, tmp_path):
    har = tmp_path / "session.har"
    make_har(har)
    svc = DapiService(ws)
    res = svc.traffic_import(str(har))
    assert res == {"format": "har", "entries": 5, "recorded": 4, "skipped": 1}
    eps = {(e["method"], e["path"]): e for e in svc.endpoints_discover()["endpoints"]}
    assert ("GET", "/v2/orders/{order_id}") in eps
    assert eps[("GET", "/v2/orders/{order_id}")]["auth"] == "yes"
    auth = svc.auth_analyze("shop.example.com")
    assert auth["login"][0]["grant_type"] == "password"
    assert auth["mechanisms"][0]["issued_by"][0]["location"] == "body:$.access_token"
    deps = svc.dependencies_discover()
    assert any(
        e["from_field"] == "$.orders[].order_id" and e["to_field"] == "path:order_id" for e in deps["edges"]
    )
    assert "har-secret-pw" not in json.dumps([svc.traffic_get(i) for i in range(1, 5)])


def test_mcp_server_over_stdio(recorded):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    ws, _ = recorded
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "dapi.cli", "--home", str(ws.home), "mcp"], env={**os.environ}
    )

    async def run():
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            assert {
                "dapi_status",
                "capture_start",
                "traffic_list",
                "traffic_get",
                "endpoints_discover",
                "endpoint_get",
                "schema_infer",
                "auth_analyze",
                "dependencies_discover",
                "session_verify",
                "session_refresh",
                "credentials_list",
                "client_generate",
                "docs_generate",
            } <= tools
            outputs = []
            for name, args in [
                ("dapi_status", {}),
                ("endpoints_discover", {}),
                ("auth_analyze", {}),
                ("traffic_get", {"flow_id": 3}),
                ("credentials_list", {}),
                ("session_verify", {"probe_auth": True}),
            ]:
                result = await session.call_tool(name, args)
                is_error = (
                    getattr(result, "is_error", None) if hasattr(result, "is_error") else result.isError
                )
                assert not is_error, (name, result.content)
                outputs.append(result.content[0].text)
            prompts = await session.list_prompts()
            assert prompts.prompts[0].name == "reverse_engineer"
            return outputs

    outputs = anyio.run(run)
    text = "\n".join(outputs)
    assert "demo-password" not in text and "eyJ" not in text
    assert '"valid": true' in text.replace(" ", "").replace('"valid":true', '"valid": true')


def test_cli(recorded, tmp_path, capsys):
    ws, base = recorded
    home = ["--home", str(ws.home)]
    cli_main([*home, "endpoints"])
    out = capsys.readouterr().out
    assert "/api/v1/projects/{project_id}/tasks" in out
    cli_main([*home, "auth"])
    assert "issued by" in capsys.readouterr().out
    cli_main([*home, "generate", "--lang", "typescript", "-o", str(tmp_path / "c")])
    assert json.loads(capsys.readouterr().out)["language"] == "typescript"
    cli_main([*home, "docs", "--format", "markdown", "-o", str(tmp_path / "API.md")])
    assert (tmp_path / "API.md").exists()
    cli_main([*home, "mcp-config", "--client", "json"])
    assert "mcpServers" in capsys.readouterr().out
    script = tmp_path / "show_env.py"
    script.write_text(
        "import os; print(bool(os.environ.get('LOCAL_API_TOKEN')), os.environ['LOCAL_API_BASE_URL'])"
    )
    proc = subprocess.run(
        [sys.executable, "-m", "dapi.cli", *home, "run", "--", sys.executable, str(script)],
        capture_output=True,
        text=True,
    )
    assert proc.stdout.split() == ["True", base]


def test_manual_session(ws, demo, monkeypatch):
    # a user who already has a token (e.g. from the browser) can register it without a capture of the login
    import httpx as _httpx

    tokens = _httpx.post(
        f"{demo}/api/v1/auth/login", json={"username": "demo", "password": "demo-password"}
    ).json()
    with _httpx.Client() as c:  # one unauthenticated observation so the origin is in the catalog
        from dapi.capture.httpx_recorder import RecordingTransport

        c._transport = RecordingTransport(ws)
        c.get(f"{demo}/api/v1/me", headers={"Authorization": "Bearer stale-token-123"})
        c.get(f"{demo}/api/v1/public/health")
    from dapi.session import set_manual_session

    set_manual_session(ws, demo, {"Authorization": f"Bearer {tokens['access_token']}"}, {})
    svc = DapiService(Workspace(ws.home))
    report = svc.session_verify(
        endpoint_ids=[
            e["id"] for e in svc.endpoints_discover()["endpoints"] if e["path"] == "/api/v1/public/health"
        ]
    )
    assert report["session"]["source"] == "manual"
    assert tokens["access_token"] not in json.dumps(report)


def _self_signed(tmp_path):
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


def test_https_capture_through_mitmproxy(ws, tmp_path):
    import ssl
    import threading
    from pathlib import Path

    from demo_api import serve

    cert, key = _self_signed(tmp_path)
    server = serve(0)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"https://127.0.0.1:{server.server_address[1]}"

    svc = DapiService(ws)
    started = svc.capture_start(port=free_port(), scope=["127.0.0.1"], ssl_insecure=True)
    ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    try:
        with httpx.Client(
            proxy=started["proxy_url"], verify=ssl.create_default_context(cafile=str(ca)), timeout=10
        ) as c:
            run_demo_session(c, base)
    finally:
        svc.capture_stop()
        server.shutdown()
    flows = svc.traffic_list(limit=100)
    assert flows["total"] == 13 and flows["flows"][0]["url"].startswith("https://127.0.0.1:")
    auth = svc.auth_analyze()
    assert auth["origin"] == base
    assert any(m["type"] == "bearer" for m in auth["mechanisms"])
    detail = svc.traffic_get(3)
    assert detail["request"]["body"]["password"].startswith("{{secret:")
