"""High-level operations shared by the MCP server and the CLI.

Every public method returns JSON-serialisable data that has passed through
the vault scrubber, so it is safe to hand to a language model: secret values
only ever appear as ``{{secret:s_...}}`` references.
"""

from __future__ import annotations

import functools
import json
import time
from pathlib import Path
from typing import Any

from dapi.analysis import analyze
from dapi.analysis.catalog import parse_json
from dapi.capture import runner
from dapi.capture.convert import import_file
from dapi.codegen import generate_client, generate_docs
from dapi.session import match_origin, refresh_session, verify_session
from dapi.workspace import Workspace

MAX_STRING = 20000


def _truncate(obj: Any, limit: int = MAX_STRING) -> Any:
    if isinstance(obj, str) and len(obj) > limit:
        return obj[:limit] + f"... <truncated {len(obj) - limit} chars>"
    if isinstance(obj, dict):
        return {k: _truncate(v, limit) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_truncate(v, limit) for v in obj]
    return obj


def safe(fn):
    """Scrub and truncate every result before it leaves dapi."""

    @functools.wraps(fn)
    def wrapper(self: DapiService, *args: Any, **kwargs: Any) -> Any:
        self._sync()
        result = fn(self, *args, **kwargs)
        return _truncate(self.ws.vault.scrub_obj(json.loads(json.dumps(result, default=str))))

    return wrapper


def _body_preview(body: str | None, content_type: str, limit: int) -> Any:
    if body is None:
        return None
    data = parse_json(body) if len(body) <= limit * 4 else None
    if data is not None and len(body) <= limit:
        return data
    return body[:limit] + (f"... <truncated, {len(body)} chars>" if len(body) > limit else "")


class DapiService:
    def __init__(self, workspace: Workspace | None = None):
        self.ws = workspace or Workspace()
        self._rev: tuple[int, int] | None = None

    def _sync(self) -> None:
        """Pick up flows/secrets written by other processes (e.g. a running capture)."""
        rev = self.ws.store.revision()
        if rev != self._rev:
            self.ws.vault.invalidate()
            self._rev = rev

    def _origin(self, origin: str | None) -> str:
        return match_origin(analyze(self.ws), origin)

    def _out_dir(self, sub: str) -> Path:
        return self.ws.home.parent / "dapi_generated" / sub

    # -- overview & capture --------------------------------------------------------------------
    @safe
    def status(self) -> dict[str, Any]:
        a = analyze(self.ws)
        return {
            "workspace": str(self.ws.home),
            "flows": self.ws.store.flow_count(),
            "origins": [
                {
                    "origin": o,
                    "endpoints": len(a.catalog.for_origin(o)),
                    "flows": sum(len(e.flow_ids) for e in a.catalog.for_origin(o)),
                }
                for o in a.catalog.origins()
            ],
            "secrets_vaulted": len(self.ws.vault.list()),
            "vault_key_source": self.ws.vault.key_source,
            "scope": self.ws.config.scope or "(everything; set a scope to restrict recording)",
            "capture": runner.status(self.ws),
            "next_steps": self._next_steps(a),
        }

    def _next_steps(self, a) -> list[str]:
        if not a.catalog.endpoints:
            return [
                "Start a capture (capture_start) and use the app through the proxy, or import a HAR (traffic_import)."
            ]
        steps = ["endpoints_discover to review the catalog", "auth_analyze to map login/refresh/token usage"]
        steps.append(
            "session_verify(probe_auth=true) to confirm the session works and which credentials are required"
        )
        steps.append("client_generate to emit a Python or TypeScript client")
        return steps

    @safe
    def capture_start(
        self,
        port: int = 8080,
        scope: list[str] | None = None,
        mode: str | None = None,
        listen_host: str = "127.0.0.1",
        ssl_insecure: bool = False,
    ) -> dict[str, Any]:
        if scope:
            self.ws.config.scope = scope
            self.ws.save_config()
        return runner.start_background(self.ws, port, scope, mode, listen_host, ssl_insecure=ssl_insecure)

    @safe
    def capture_stop(self) -> dict[str, Any]:
        return runner.stop_background(self.ws)

    @safe
    def traffic_import(self, path: str) -> dict[str, Any]:
        result = import_file(self.ws, Path(path).expanduser())
        self.ws.invalidate()
        return result

    @safe
    def scope_set(self, hosts: list[str], ignore_hosts: list[str] | None = None) -> dict[str, Any]:
        self.ws.config.scope = hosts
        if ignore_hosts is not None:
            self.ws.config.ignore_hosts = ignore_hosts
        self.ws.save_config()
        return {
            "scope": self.ws.config.scope,
            "ignore_hosts": self.ws.config.ignore_hosts,
            "note": "applies to new captures and to session verification",
        }

    # -- traffic -------------------------------------------------------------------------------
    @safe
    def traffic_list(
        self,
        origin: str | None = None,
        method: str | None = None,
        path_contains: str | None = None,
        status: int | None = None,
        endpoint_id: str | None = None,
        source: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        a = analyze(self.ws)
        ep_filter = a.endpoint(endpoint_id).id if endpoint_id else None
        rows = []
        for ex in a.ctx.flows.values():
            if origin and origin.rstrip("/") not in (ex.origin, ex.host):
                continue
            if method and ex.method != method.upper():
                continue
            if path_contains and path_contains not in ex.path:
                continue
            if status is not None and ex.status != status:
                continue
            if source and ex.source != source:
                continue
            ep = a.catalog.flow_endpoint.get(ex.id)
            if ep_filter and ep != ep_filter:
                continue
            rows.append({**ex.summary(), "endpoint_id": ep})
        rows.sort(key=lambda r: r["id"])
        limit = max(1, min(limit, 500))
        return {"total": len(rows), "offset": offset, "flows": rows[offset : offset + limit]}

    @safe
    def traffic_get(self, flow_id: int, max_body_chars: int = 4000) -> dict[str, Any]:
        ex = self.ws.store.get_flow(flow_id)
        if ex is None:
            raise KeyError(f"no flow #{flow_id}")
        a = analyze(self.ws)
        return {
            **ex.summary(),
            "endpoint_id": a.catalog.flow_endpoint.get(flow_id),
            "duration_ms": ex.duration_ms,
            "request": {
                "headers": ex.req_headers,
                "query": ex.query,
                "content_type": ex.req_content_type or None,
                "body": _body_preview(ex.req_body, ex.req_content_type, max_body_chars),
            },
            "response": {
                "status": ex.status,
                "headers": ex.resp_headers,
                "content_type": ex.resp_content_type or None,
                "body": _body_preview(ex.resp_body, ex.resp_content_type, max_body_chars),
            },
            "secrets": [
                {
                    "ref": s.ref,
                    "side": s.side,
                    "location": s.location,
                    "kind": self.ws.vault.meta(s.ref).get("kind"),
                }
                for s in self.ws.store.sightings(flow_id=flow_id)
            ],
        }

    @safe
    def traffic_search(self, text: str, limit: int = 30) -> dict[str, Any]:
        hits = []
        for ex in self.ws.store.iter_flows():
            fields = {
                "url": ex.path + "?" + "&".join(f"{k}={v}" for k, v in ex.query),
                "request_headers": json.dumps(ex.req_headers),
                "request_body": ex.req_body or "",
                "response_headers": json.dumps(ex.resp_headers),
                "response_body": ex.resp_body or "",
            }
            where = [k for k, v in fields.items() if text.lower() in v.lower()]
            if where:
                hits.append({**ex.summary(), "matched_in": where})
                if len(hits) >= limit:
                    break
        return {"query": text, "hits": hits}

    # -- catalog -------------------------------------------------------------------------------
    @safe
    def endpoints_discover(self, origin: str | None = None) -> dict[str, Any]:
        a = analyze(self.ws)
        eps = a.catalog.for_origin(origin)
        return {
            "origins": sorted({e.origin for e in eps}),
            "count": len(eps),
            "endpoints": [e.summary() for e in eps],
            "legend": {
                "auth": "yes = rejected without credentials; likely = credentials always sent but unconfirmed; "
                "no = succeeded without credentials"
            },
        }

    @safe
    def endpoint_get(self, endpoint_id: str) -> dict[str, Any]:
        a = analyze(self.ws)
        ep = a.endpoint(endpoint_id)
        data = ep.to_dict()
        data["dependencies"] = a.dependencies(endpoint_id=ep.id)["edges"]
        return data

    @safe
    def schema_infer(
        self, endpoint_id: str, part: str = "response", status: str | None = None
    ) -> dict[str, Any]:
        a = analyze(self.ws)
        ep = a.endpoint(endpoint_id)
        if part == "request":
            return {
                "endpoint": ep.key,
                "part": "request",
                "content_types": ep.request_content_types,
                "schema": ep.request_schema,
                "query_params": ep.query_params,
                "path_params": ep.path_params,
            }
        if status is None:
            ok = ep.success_statuses()
            status = str(ok[0]) if ok else next(iter(ep.responses), None)
        resp = ep.responses.get(str(status)) if status else None
        if resp is None:
            raise KeyError(f"no responses with status {status} observed; seen: {sorted(ep.responses)}")
        return {
            "endpoint": ep.key,
            "part": "response",
            "status": status,
            "content_types": resp["content_types"],
            "schema": resp["schema"],
            "samples": resp["count"],
            "evidence_flows": resp["flow_ids"],
        }

    # -- auth & sessions -------------------------------------------------------------------------
    @safe
    def auth_analyze(self, origin: str | None = None) -> dict[str, Any]:
        a = analyze(self.ws)
        if origin or len(a.catalog.origins()) == 1:
            o = self._origin(origin)
            return {"origin": o, **a.auth_for(o)}
        return a.auth

    @safe
    def dependencies_discover(
        self, endpoint_id: str | None = None, origin: str | None = None
    ) -> dict[str, Any]:
        return analyze(self.ws).dependencies(endpoint_id=endpoint_id, origin=origin)

    @safe
    def session_verify(
        self,
        origin: str | None = None,
        endpoint_ids: list[str] | None = None,
        probe_auth: bool = False,
        refresh_if_needed: bool = True,
        allow_login: bool = False,
        max_endpoints: int = 3,
    ) -> dict[str, Any]:
        return verify_session(
            self.ws, origin, endpoint_ids, max_endpoints, probe_auth, refresh_if_needed, allow_login
        )

    @safe
    def session_refresh(self, origin: str | None = None, allow_login: bool = False) -> dict[str, Any]:
        return refresh_session(self.ws, origin, allow_login)

    @safe
    def credentials_list(self, origin: str | None = None) -> dict[str, Any]:
        now = time.time()
        out = []
        for item in self.ws.vault.list():
            if origin and origin.rstrip("/") not in str(item.get("origin", "")):
                continue
            exp = (item.get("jwt") or {}).get("exp") or item.get("expires_at")
            entry = {k: v for k, v in item.items() if k not in {"placeholder"}}
            if isinstance(exp, int | float):
                entry["expires_in_seconds"] = int(exp - now)
            out.append(entry)
        return {
            "note": "values are encrypted in the vault and never returned; use refs/placeholders",
            "credentials": out,
        }

    # -- generation ----------------------------------------------------------------------------
    @safe
    def client_generate(
        self,
        origin: str | None = None,
        language: str = "python",
        output_dir: str | None = None,
        endpoint_ids: list[str] | None = None,
        class_name: str | None = None,
    ) -> dict[str, Any]:
        a = analyze(self.ws)
        o = self._origin(origin)
        out = Path(output_dir).expanduser() if output_dir else self._out_dir("clients")
        result = generate_client(a, o, language, out, endpoint_ids, class_name, self.ws.store.flow_count())
        result["usage"] = _usage(result)
        return result

    @safe
    def docs_generate(
        self, origin: str | None = None, format: str = "openapi", output_path: str | None = None
    ) -> dict[str, Any]:
        a = analyze(self.ws)
        o = self._origin(origin)
        ext = ".json" if format == "openapi" else ".md"
        path = (
            Path(output_path).expanduser()
            if output_path
            else self._out_dir("docs") / f"{o.split('://')[1].replace(':', '_')}{ext}"
        )
        return generate_docs(a, o, format, path, self.ws.store.flow_count())


def _usage(result: dict[str, Any]) -> list[str]:
    cls, prefix = result["class_name"], result["env_prefix"]
    if result["language"] == "python":
        return [
            f"from {Path(result['path']).stem} import {cls}",
            f"client = {cls}.from_dapi()   # reuse the captured/verified session (no manual login)",
            f"client = {cls}.from_env()    # or read {prefix}_TOKEN / {prefix}_USERNAME / {prefix}_PASSWORD ...",
            f"client = {cls}(username=..., password=...); client.login()",
        ]
    return [
        f"import {{ {cls} }} from './{Path(result['path']).stem}';",
        f"const client = {cls}.fromEnv(); // {prefix}_TOKEN etc.; `dapi run -- node script.mjs` injects them",
    ]
