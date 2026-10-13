import json

from dapi.models import RawExchange
from dapi.redact import classify_key, jwt_claims
from dapi.vault import PLACEHOLDER_RE

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE5MDAwMDAwMDAsImlhdCI6MTgwMDAwMDAwMCwic3ViIjoiYWxpY2UifQ.c2lnbmF0dXJl"


def ingest(ws, **kw):
    defaults = dict(method="GET", url="https://api.example.com/x", req_headers=[], status=200, ts=1000.0)
    defaults.update(kw)
    fid = ws.ingest(RawExchange(**defaults))
    return ws.store.get_flow(fid)


def test_classify_key():
    assert classify_key("password") == "password"
    assert classify_key("newPassword") == "password"
    assert classify_key("refresh_token") == "refresh_token"
    assert classify_key("accessToken") == "access_token"
    assert classify_key("X-API-Key") == "api_key"
    assert classify_key("csrfmiddlewaretoken") == "csrf"
    assert classify_key("token_type") is None
    assert classify_key("expires_in") is None
    assert classify_key("username") is None
    assert classify_key("country_code") is None


def test_headers_cookies_and_set_cookie(ws):
    f = ingest(
        ws,
        req_headers=[
            ("Authorization", "Bearer abcdef123456"),
            ("Cookie", "sid=s3cr3tvalue; theme=dark"),
            ("X-Api-Key", "key-998877"),
            ("Accept", "application/json"),
        ],
        resp_headers=[("Set-Cookie", "sid=newsecret999; Path=/; Max-Age=60; HttpOnly")],
    )
    hdrs = dict(f.req_headers)
    assert hdrs["Authorization"].startswith("Bearer {{secret:")
    assert "s3cr3tvalue" not in hdrs["Cookie"] and hdrs["Cookie"].startswith("sid={{secret:")
    assert PLACEHOLDER_RE.fullmatch(hdrs["X-Api-Key"])
    assert hdrs["Accept"] == "application/json"
    set_cookie = dict(f.resp_headers)["Set-Cookie"]
    assert "newsecret999" not in set_cookie and "Max-Age=60" in set_cookie
    meta = next(m for m in ws.vault.list() if m.get("name") == "sid" and m.get("cookie_attrs"))
    assert meta["cookie_attrs"]["max_age"] == 60 and meta["expires_at"] == 1060.0


def test_json_body_login_and_tokens(ws):
    f = ingest(
        ws,
        method="POST",
        req_headers=[("Content-Type", "application/json")],
        req_body=json.dumps({"email": "a@b.co", "password": "hunter2!", "remember": True}).encode(),
        resp_headers=[("Content-Type", "application/json")],
        resp_body=json.dumps(
            {"data": {"accessToken": JWT, "expiresIn": 900, "refreshToken": "rt-0123456789"}}
        ).encode(),
    )
    req = json.loads(f.req_body)
    assert PLACEHOLDER_RE.fullmatch(req["email"]), "identity next to a password is vaulted"
    assert PLACEHOLDER_RE.fullmatch(req["password"]) and req["remember"] is True
    resp = json.loads(f.resp_body)["data"]
    assert PLACEHOLDER_RE.fullmatch(resp["accessToken"]) and resp["expiresIn"] == 900
    kinds = {m["kind"] for m in ws.vault.list()}
    assert {"username", "password", "access_token", "refresh_token"} <= kinds
    access = next(m for m in ws.vault.list() if m["kind"] == "access_token")
    assert access["jwt"] == {"exp": 1900000000, "iat": 1800000000}, "only timing claims are kept"
    assert access["expires_in"] == 900


def test_form_query_and_patterns(ws):
    f = ingest(
        ws,
        method="POST",
        url=f"https://api.example.com/cb?code=authcode123&state=xyz&page=2&jwt={JWT}",
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body=b"grant_type=password&username=bob&password=p%40ss+word&client_id=web",
        resp_headers=[("Content-Type", "text/plain")],
        resp_body=f"echo {JWT} and Bearer zzzzzzzzzz12".encode(),
    )
    q = dict(f.query)
    assert PLACEHOLDER_RE.fullmatch(q["code"]) and q["state"] == "xyz" and q["page"] == "2"
    assert PLACEHOLDER_RE.fullmatch(q["jwt"])
    assert "grant_type=password" in f.req_body and "client_id=web" in f.req_body
    assert "bob" not in f.req_body and "p%40ss" not in f.req_body
    assert JWT not in f.resp_body and "zzzzzzzzzz12" not in f.resp_body
    assert ws.vault.reveal(next(m["ref"] for m in ws.vault.list() if m["kind"] == "password")) == "p@ss word"


def test_known_values_are_scrubbed_everywhere(ws):
    ingest(ws, req_headers=[("Authorization", "Bearer reflected-token-42")])
    f = ingest(
        ws,
        resp_headers=[("Content-Type", "text/html")],
        resp_body=b"<p>your token: reflected-token-42 / reflected%2Dtoken%2D42</p>",
    )
    assert "reflected-token-42" not in f.resp_body
    assert ws.vault.scrub("x reflected-token-42 y") != "x reflected-token-42 y"


def test_deterministic_refs_link_issue_and_use(ws):
    issued = ingest(
        ws,
        method="POST",
        resp_headers=[("Content-Type", "application/json")],
        resp_body=json.dumps({"token": "opaque-token-777"}).encode(),
    )
    used = ingest(ws, req_headers=[("X-Auth-Token", "opaque-token-777")])
    ref_issued = PLACEHOLDER_RE.search(issued.resp_body).group(1)
    ref_used = PLACEHOLDER_RE.search(dict(used.req_headers)["X-Auth-Token"]).group(1)
    assert ref_issued == ref_used


def test_nothing_secret_hits_disk(ws):
    from conftest import raw_storage_bytes

    ingest(
        ws,
        method="POST",
        req_headers=[("Content-Type", "application/json"), ("Authorization", "Bearer disk-token-1")],
        req_body=json.dumps({"username": "u", "password": "disk-password-1"}).encode(),
        resp_headers=[("Content-Type", "application/json"), ("Set-Cookie", "sid=disk-cookie-1")],
        resp_body=json.dumps({"access_token": JWT}).encode(),
    )
    ws.store._conn.execute("PRAGMA wal_checkpoint(FULL)")
    blob = raw_storage_bytes(ws)
    for secret in (b"disk-token-1", b"disk-password-1", b"disk-cookie-1", JWT.encode()):
        assert secret not in blob


def test_vault_roundtrip_and_key_isolation(ws, tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    from dapi import Workspace

    ref = ws.vault.put("value-xyz-123", "token")
    assert ws.vault.reveal(ref) == "value-xyz-123"
    assert ws.vault.resolve("a {{secret:" + ref + "}} b") == "a value-xyz-123 b"
    assert oct((ws.home / "vault.key").stat().st_mode)[-3:] == "600"
    monkeypatch.setenv("DAPI_VAULT_KEY", Fernet.generate_key().decode())
    other = Workspace(tmp_path / "other")
    assert other.vault.key_source == "env:DAPI_VAULT_KEY"


def test_jwt_claims_filtering():
    assert jwt_claims(JWT) == {"exp": 1900000000, "iat": 1800000000}
    assert jwt_claims("not.a.jwt") is None


def test_scope_and_static_filtering(ws):
    ws.config.scope = ["*.example.com"]
    assert ws.ingest(RawExchange("GET", "https://api.example.com/a", [], status=200)) is not None
    assert ws.ingest(RawExchange("GET", "https://tracker.other.net/a", [], status=200)) is None
    assert ws.ingest(RawExchange("GET", "https://api.example.com/app.js", [], status=200)) is None
    assert (
        ws.ingest(
            RawExchange(
                "GET",
                "https://example.com/logo",
                [],
                status=200,
                resp_headers=[("Content-Type", "image/png")],
            )
        )
        is None
    )


def test_tool_errors_are_scrubbed(ws):
    import pytest

    from dapi.service import DapiError, DapiService

    ws.vault.put("leaky-secret-value-9", "token")
    svc = DapiService(ws)

    def boom(*a, **k):
        raise ValueError(
            "upstream said: leaky-secret-value-9 and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2ln"
        )

    svc.ws.store.get_flow = boom
    with pytest.raises(DapiError) as err:
        svc.traffic_get(1)
    assert "leaky-secret-value-9" not in str(err.value) and "eyJ" not in str(err.value)
    assert "{{secret:" in str(err.value)
