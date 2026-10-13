"""Session management and verification.

A *session* is the set of credential-bearing headers and cookies needed to
call an origin, stored as templates containing ``{{secret:...}}``
placeholders. Sessions are derived from evidence: the most recent successful
authenticated request, with each credential advanced to the newest value
issued at the same place (so a token refreshed by dapi, or by the app while
capturing, is picked up automatically).

Verification only ever sends safe, read-only requests (GET/HEAD to endpoints
whose paths do not look state-changing) to origins that are in scope and
already present in the catalog. Login replay is opt-in.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import httpx

from dapi.analysis import Analysis, Endpoint, analyze
from dapi.analysis.auth import AuthContext
from dapi.analysis.catalog import flow_succeeded, parse_json
from dapi.analysis.schema import check
from dapi.models import Exchange, RawExchange, is_form_type, is_json_type
from dapi.redact import parse_cookie_header
from dapi.vault import PLACEHOLDER_RE, Vault, refs_in
from dapi.workspace import Workspace

SKIP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "cookie",
    "transfer-encoding",
    "te",
    "keep-alive",
    "upgrade",
    "proxy-connection",
    "proxy-authorization",
    "http2-settings",
}
SAFE_VERIFY_METHODS = {"GET", "HEAD"}


def succeeded(ep: Endpoint, resp: httpx.Response) -> bool:
    """2xx, and for GraphQL also not an ``errors``-only payload (servers often reject auth with 200)."""
    if not 200 <= resp.status_code < 300:
        return False
    if ep.graphql:
        try:
            body = resp.json()
        except ValueError:
            return False
        if isinstance(body, dict) and body.get("errors") and not body.get("data"):
            return False
    return True


def verifiable(ep: Endpoint) -> bool:
    """Safe to call during verification: read-only GET/HEAD, or a GraphQL *query* operation."""
    if not ep.read_only:
        return False
    return ep.method in SAFE_VERIFY_METHODS or bool(ep.graphql and ep.graphql["operation_type"] == "query")


@dataclass
class Session:
    origin: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    source: str = ""
    updated: float = 0.0

    def refs(self) -> list[str]:
        return [r for v in [*self.headers.values(), *self.cookies.values()] for r in refs_in(v)]

    def describe(self, vault: Vault) -> dict[str, Any]:
        """Model-safe description: header/cookie names, placeholders and expiry, never values."""
        now = time.time()
        creds = []
        for kind, items in (("header", self.headers), ("cookie", self.cookies)):
            for name, template in items.items():
                for ref in refs_in(template):
                    meta = vault.meta(ref)
                    exp = (meta.get("jwt") or {}).get("exp") or meta.get("expires_at")
                    entry = {"location": f"{kind}:{name}", "ref": ref, "kind": meta.get("kind")}
                    if isinstance(exp, int | float):
                        entry["expires_in_seconds"] = int(exp - now)
                        entry["expired"] = exp <= now
                    creds.append(entry)
        return {"origin": self.origin, "source": self.source, "credentials": creds}


def _advance(ctx: AuthContext, template: str) -> str:
    return PLACEHOLDER_RE.sub(lambda m: "{{secret:" + ctx.latest_in_lineage(m.group(1)) + "}}", template)


def current_session(ws: Workspace, analysis: Analysis, origin: str) -> Session | None:
    ctx = analysis.ctx
    derived: Session | None = None
    flows = sorted(
        (f for f in ctx.flows.values() if f.origin == origin), key=lambda f: (f.ts, f.id), reverse=True
    )
    for f in flows:
        ep = ctx.endpoint_of(f.id)
        if not flow_succeeded(f, ep):
            continue
        if ep and set(ep.tags) & {"login", "refresh", "logout"}:
            continue
        pres = ctx.presentations(f.id)
        if not pres:
            continue
        sess = Session(origin=origin, source=f"observed flow #{f.id}", updated=f.ts)
        locations = {p.location for p in pres}
        for name, value in f.req_headers:
            if f"header:{name}" in locations:
                sess.headers[name] = _advance(ctx, value)
            elif name.lower() == "cookie":
                for c_name, c_val in parse_cookie_header(value):
                    if f"cookie:{c_name}" in locations:
                        sess.cookies[c_name] = _advance(ctx, c_val)
        derived = sess
        break
    stored = ws.store.get_session(origin)
    if stored:
        data, updated = stored
        manual = Session(
            origin=origin,
            headers=data.get("headers", {}),
            cookies=data.get("cookies", {}),
            source=data.get("source", "manual"),
            updated=updated,
        )
        if derived is None or manual.updated >= derived.updated:
            return manual
    return derived


def set_manual_session(
    ws: Workspace, origin: str, headers: dict[str, str], cookies: dict[str, str]
) -> Session:
    """Store a user-supplied session. Values are vaulted; only templates are persisted."""

    def vaulted(name: str, value: str, kind: str) -> str:
        if PLACEHOLDER_RE.search(value):
            return value
        if kind == "header" and name.lower() == "authorization" and " " in value:
            scheme, cred = value.split(" ", 1)
            return (
                f"{scheme} "
                + "{{secret:"
                + ws.vault.put(cred, "bearer", {"origin": origin, "manual": True})
                + "}}"
            )
        return (
            "{{secret:"
            + ws.vault.put(
                value,
                "cookie" if kind == "cookie" else "token",
                {"origin": origin, "name": name, "manual": True},
            )
            + "}}"
        )

    data = {
        "headers": {k: vaulted(k, v, "header") for k, v in headers.items()},
        "cookies": {k: vaulted(k, v, "cookie") for k, v in cookies.items()},
        "source": "manual",
    }
    ws.store.put_session(origin, data)
    ws.invalidate()
    return Session(
        origin=origin, headers=data["headers"], cookies=data["cookies"], source="manual", updated=time.time()
    )


def resolve_session(ws: Workspace, origin_or_host: str) -> dict[str, Any]:
    """Return a session with real credential values, for use by *programs* (generated clients, ``dapi run``).

    Never pass the result of this function back to a language model.
    """
    analysis = analyze(ws)
    origin = match_origin(analysis, origin_or_host)
    sess = current_session(ws, analysis, origin)
    if sess is None:
        raise LookupError(f"no authenticated session observed for {origin}")
    refresh_ref = analysis.ctx.latest_issued(origin, "refresh_token")
    return {
        "base_url": origin,
        "headers": {k: ws.vault.resolve(v) for k, v in sess.headers.items()},
        "cookies": {k: ws.vault.resolve(v) for k, v in sess.cookies.items()},
        "refresh_token": ws.vault.reveal(refresh_ref) if refresh_ref else None,
    }


def match_origin(analysis: Analysis, origin_or_host: str | None) -> str:
    origins = analysis.catalog.origins()
    if not origins:
        raise LookupError("no traffic captured yet: run a capture or import a HAR first (check the scope)")
    if not origin_or_host:
        if len(origins) == 1:
            return origins[0]
        raise LookupError(f"several origins captured; pass one of: {', '.join(origins)}")
    needle = origin_or_host.lower().rstrip("/")
    for o in origins:
        if needle == o or o.endswith("://" + needle) or o.split("://", 1)[1].split(":")[0] == needle:
            return o
    raise LookupError(f"unknown origin {origin_or_host!r}; captured origins: {', '.join(origins) or 'none'}")


# -- request construction ----------------------------------------------------------------------
def _resolve_body(ws: Workspace, ctx: AuthContext, flow: Exchange) -> bytes | None:
    if flow.req_body is None or flow.req_body.startswith("<binary body"):
        return None
    advanced = _advance(ctx, flow.req_body)
    if is_json_type(flow.req_content_type):
        data = parse_json(advanced)
        if data is not None:

            def walk(o: Any) -> Any:
                if isinstance(o, str):
                    return ws.vault.resolve(o)
                if isinstance(o, list):
                    return [walk(x) for x in o]
                if isinstance(o, dict):
                    return {k: walk(v) for k, v in o.items()}
                return o

            return json.dumps(walk(data)).encode()
    if is_form_type(flow.req_content_type):
        pairs = parse_qsl(advanced, keep_blank_values=True)
        return urlencode([(k, ws.vault.resolve(v)) for k, v in pairs]).encode()
    return ws.vault.resolve(advanced).encode()


def build_request(
    ws: Workspace, ctx: AuthContext, flow: Exchange, session: Session | None, *, with_auth: bool = True
) -> httpx.Request:
    pres_locations = {p.location.lower() for p in ctx.presentations(flow.id)}
    session_headers = {k.lower() for k in (session.headers if session else {})}
    headers: list[tuple[str, str]] = []
    for name, value in flow.req_headers:
        lname = name.lower()
        if lname in SKIP_HEADERS or lname.startswith(":") or lname in session_headers:
            continue
        if f"header:{lname}" in pres_locations or (not with_auth and PLACEHOLDER_RE.search(value)):
            continue  # credential header not part of the session; drop rather than send stale values
        headers.append((name, ws.vault.resolve(_advance(ctx, value))))
    cookies: dict[str, str] = {}
    if with_auth and session:
        headers += [(k, ws.vault.resolve(v)) for k, v in session.headers.items()]
        cookies = {k: ws.vault.resolve(v) for k, v in session.cookies.items()}
    if cookies:
        headers.append(("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items())))
    query = [(k, ws.vault.resolve(_advance(ctx, v))) for k, v in flow.query]
    path = ws.vault.resolve(_advance(ctx, flow.path))
    url = flow.origin + quote(path, safe="/%:@!$&'()*+,;=-._~") + (("?" + urlencode(query)) if query else "")
    return httpx.Request(flow.method, url, headers=headers, content=_resolve_body(ws, ctx, flow))


def send_and_record(
    ws: Workspace, request: httpx.Request, source: str, timeout: float = 20.0
) -> tuple[httpx.Response | None, int | None, str | None]:
    """Send a request, record the redacted exchange as evidence, return (response, flow id, error)."""
    started = time.time()
    raw = RawExchange(
        method=request.method,
        url=str(request.url),
        req_headers=list(request.headers.multi_items()),
        req_body=request.content or None,
        ts=started,
        source=source,
    )
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            resp = client.send(request)
    except httpx.HTTPError as exc:
        raw.error = f"{type(exc).__name__}: {exc}"
        flow_id = ws.ingest(raw, force=True)
        return None, flow_id, raw.error
    raw.status = resp.status_code
    raw.resp_headers = list(resp.headers.multi_items())
    raw.resp_body = resp.content
    raw.duration_ms = (time.time() - started) * 1000
    flow_id = ws.ingest(raw, force=True)
    return resp, flow_id, None


# -- verification --------------------------------------------------------------------------------
def _evidence_flow(analysis: Analysis, ep: Endpoint) -> Exchange | None:
    flows = [analysis.ctx.flows[i] for i in ep.flow_ids if i in analysis.ctx.flows]
    ok = [f for f in flows if flow_succeeded(f, ep) and not refs_in(f.path)]
    return max(ok, key=lambda f: (f.ts, f.id)) if ok else None


def _candidates(
    analysis: Analysis, origin: str, endpoint_ids: list[str] | None
) -> tuple[list[Endpoint], list[dict]]:
    rejected = []
    if endpoint_ids:
        eps = []
        for eid in endpoint_ids:
            ep = analysis.catalog.get(eid)
            if ep is None or ep.origin != origin:
                rejected.append({"endpoint_id": eid, "reason": "unknown endpoint for this origin"})
            elif not verifiable(ep):
                rejected.append({"endpoint_id": eid, "reason": f"not read-only ({ep.read_only_reason})"})
            else:
                eps.append(ep)
        return eps, rejected
    eps = [
        e
        for e in analysis.catalog.for_origin(origin)
        if e.read_only
        and verifiable(e)
        and e.success_statuses()
        and not set(e.tags) & {"login", "refresh", "logout"}
    ]
    rank = {"yes": 0, "likely": 1, "unknown": 2, "no": 3}
    eps.sort(
        key=lambda e: (rank.get(e.auth.get("required", "unknown"), 2), len(e.path_params), -len(e.flow_ids))
    )
    return eps, rejected


def _check_endpoint(
    ws: Workspace, analysis: Analysis, ep: Endpoint, session: Session | None, timeout: float
) -> dict[str, Any]:
    flow = _evidence_flow(analysis, ep)
    result: dict[str, Any] = {"endpoint_id": ep.id, "endpoint": ep.label}
    if flow is None:
        return {**result, "ok": False, "error": "no successful evidence flow to base the request on"}
    req = build_request(ws, analysis.ctx, flow, session)
    resp, flow_id, error = send_and_record(ws, req, "dapi-verify", timeout)
    result.update({"based_on_flow": flow.id, "recorded_flow": flow_id})
    if resp is None:
        return {**result, "ok": False, "error": error}
    result["status"] = resp.status_code
    result["latency_ms"] = round(resp.elapsed.total_seconds() * 1000, 1)
    result["ok"] = succeeded(ep, resp)
    schema = (ep.responses.get(str(resp.status_code)) or {}).get("schema")
    if result["ok"] and schema:
        try:
            issues = check(schema, resp.json())
        except ValueError:
            issues = ["response is not valid JSON although JSON was observed before"]
        result["schema_matches"] = not issues
        if issues:
            result["schema_issues"] = issues[:10]
    return result


def verify_session(
    ws: Workspace,
    origin: str | None = None,
    endpoint_ids: list[str] | None = None,
    max_endpoints: int = 3,
    probe_auth: bool = False,
    refresh_if_needed: bool = True,
    allow_login: bool = False,
    timeout: float = 20.0,
) -> dict[str, Any]:
    analysis = analyze(ws)
    target = match_origin(analysis, origin)
    host = urlsplit(target).hostname or ""
    if not ws.in_scope(host):
        return {"origin": target, "error": f"{host} is outside the configured scope {ws.config.scope}"}
    session = current_session(ws, analysis, target)
    candidates, rejected = _candidates(analysis, target, endpoint_ids)
    candidates = candidates[: max(1, min(max_endpoints, 10))]
    report: dict[str, Any] = {
        "origin": target,
        "session": session.describe(ws.vault) if session else None,
        "checked": [],
        **({"rejected": rejected} if rejected else {}),
    }
    if not candidates:
        report["valid"] = False
        report["error"] = "no read-only endpoint with a successful observation to verify against"
        return report

    results = [_check_endpoint(ws, analysis, ep, session, timeout) for ep in candidates]
    if refresh_if_needed and any(r.get("status") in (401, 403) for r in results):
        report["refresh"] = refresh_session(ws, target, allow_login=allow_login, timeout=timeout)
        if report["refresh"].get("refreshed"):
            analysis = analyze(ws)
            session = current_session(ws, analysis, target)
            report["session"] = session.describe(ws.vault) if session else None
            retry = {r["endpoint_id"] for r in results if r.get("status") in (401, 403)}
            results = [
                _check_endpoint(ws, analysis, analysis.endpoint(r["endpoint_id"]), session, timeout)
                if r["endpoint_id"] in retry
                else r
                for r in results
            ]
    if probe_auth:
        for r, ep in zip(results, candidates, strict=False):
            flow = _evidence_flow(analysis, ep)
            if flow is None:
                continue
            resp, fid, err = send_and_record(
                ws, build_request(ws, analysis.ctx, flow, None, with_auth=False), "dapi-probe", timeout
            )
            status = resp.status_code if resp is not None else None
            r["unauthenticated_probe"] = {
                "status": status,
                "recorded_flow": fid,
                "auth_required": None
                if resp is None
                else (status in (401, 403) or (bool(r.get("ok")) and not succeeded(ep, resp))),
                **({"error": err} if err else {}),
            }
        report["credential_ablation"] = _ablate(ws, analysis, candidates, results, session, timeout)
    report["checked"] = results
    report["valid"] = any(r.get("ok") for r in results) and all(
        r.get("status") not in (401, 403) for r in results
    )
    ws.invalidate()
    return report


def _ablate(
    ws: Workspace,
    analysis: Analysis,
    candidates: list[Endpoint],
    results: list[dict[str, Any]],
    session: Session | None,
    timeout: float,
) -> dict[str, Any]:
    """Drop one credential at a time on a verified endpoint to learn which ones are actually required."""
    if session is None:
        return {}
    pick = next(
        (
            (ep, r)
            for ep, r in zip(candidates, results, strict=False)
            if r.get("ok") and (r.get("unauthenticated_probe") or {}).get("auth_required")
        ),
        None,
    )
    if pick is None:
        return {"skipped": "no endpoint both succeeded with credentials and failed without them"}
    ep, _ = pick
    flow = _evidence_flow(analysis, ep)
    if flow is None:
        return {}
    necessary: dict[str, bool | None] = {}
    locations = [("header", k) for k in session.headers] + [("cookie", k) for k in session.cookies]
    if len(locations) < 2:
        if locations:
            necessary[
                f"{locations[0][0]}:{locations[0][1].lower() if locations[0][0] == 'header' else locations[0][1]}"
            ] = True
    else:
        for kind, name in locations:
            reduced = Session(
                origin=session.origin,
                source=session.source,
                updated=session.updated,
                headers={k: v for k, v in session.headers.items() if not (kind == "header" and k == name)},
                cookies={k: v for k, v in session.cookies.items() if not (kind == "cookie" and k == name)},
            )
            resp, _, _ = send_and_record(
                ws, build_request(ws, analysis.ctx, flow, reduced), "dapi-probe", timeout
            )
            loc = f"header:{name.lower()}" if kind == "header" else f"cookie:{name}"
            necessary[loc] = None if resp is None else not succeeded(ep, resp)
    ws.store.kv_set(
        f"ablation:{session.origin}", {"endpoint": ep.id, "necessary": necessary, "ts": time.time()}
    )
    return {"endpoint_id": ep.id, "necessary": necessary}


def refresh_session(
    ws: Workspace, origin: str | None = None, allow_login: bool = False, timeout: float = 20.0
) -> dict[str, Any]:
    """Obtain fresh credentials by replaying the observed refresh flow (or, if allowed, the login flow)."""
    analysis = analyze(ws)
    target = match_origin(analysis, origin)
    auth = analysis.auth_for(target)
    attempts: list[dict[str, Any]] = []
    plans = [("refresh", item) for item in auth.get("refresh", []) if item.get("successful_flows")]
    if allow_login:
        plans += [("login", item) for item in auth.get("login", []) if item.get("successful_flows")]
    if not plans:
        hint = "" if allow_login else " (login replay is disabled; pass allow_login=true to permit it)"
        return {"refreshed": False, "reason": "no successful refresh flow observed" + hint}
    for how, item in plans:
        flow = analysis.ctx.flows[item["successful_flows"][-1]]
        req = build_request(ws, analysis.ctx, flow, current_session(ws, analysis, target))
        resp, flow_id, error = send_and_record(ws, req, f"dapi-{how}", timeout)
        attempt = {
            "method": how,
            "endpoint": item["endpoint"],
            "based_on_flow": flow.id,
            "recorded_flow": flow_id,
        }
        if resp is None:
            attempts.append({**attempt, "error": error})
            continue
        attempt["status"] = resp.status_code
        new = [s.location for s in ws.store.sightings(flow_id=flow_id) if s.side == "response"]
        # logins often answer with a redirect; count it only if it actually issued credentials
        if 200 <= resp.status_code < 300 or (300 <= resp.status_code < 400 and new):
            ws.invalidate()
            attempts.append({**attempt, "new_credentials": new})
            # a fresh observed session supersedes any stale manual one
            if ws.store.get_session(target):
                ws.store.delete_session(target)
            return {"refreshed": True, **attempts[-1], "attempts": attempts}
        attempts.append(attempt)
    return {"refreshed": False, "attempts": attempts}


def session_dict(session: Session | None) -> dict[str, Any] | None:
    return asdict(session) if session else None
