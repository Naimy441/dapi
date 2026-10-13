"""Language-neutral client specification derived from the catalog and auth model.

Generators (Python, TypeScript) render this spec; they never look at raw
traffic. Everything in the spec cites the flows it came from.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from dapi.analysis import Analysis, Endpoint
from dapi.analysis.catalog import parse_json, singular
from dapi.models import is_form_type, media_type
from dapi.vault import PLACEHOLDER_RE

VERBS = {
    "GET": "get",
    "POST": "create",
    "PUT": "replace",
    "PATCH": "update",
    "DELETE": "delete",
    "HEAD": "head",
    "OPTIONS": "options",
}
MECHANISM_PRIORITY = [
    "bearer",
    "api_key_header",
    "authorization_header",
    "header_token",
    "basic",
    "cookie",
    "query_token",
]


def snake(text: str) -> str:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").lower()
    if not s:
        return "value"
    return "_" + s if s[0].isdigit() else s


def pascal(text: str) -> str:
    return "".join(p[:1].upper() + p[1:] for p in snake(text).split("_")) or "Model"


def location_path(location: str) -> list[str] | None:
    """``body:$.data.access_token`` -> ``["data", "access_token"]`` (None for non-body locations)."""
    if not location.startswith("body:$"):
        return None
    rest = location[len("body:$") :].lstrip(".")
    if "[]" in rest:
        return None
    return [p for p in rest.split(".") if p] if rest else []


@dataclass
class Param:
    name: str  # identifier in generated code
    wire: str  # name on the wire
    type: str  # json-schema primitive: string | integer | number | boolean
    required: bool = True
    examples: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class Operation:
    name: str
    method: str
    path: str  # template with {wire} params
    endpoint_id: str
    path_params: list[Param]
    query_params: list[Param]
    body_kind: str | None  # "json" | "form" | None
    body_schema: dict[str, Any]
    body_required: bool
    response_schema: dict[str, Any]
    response_status: str | None
    response_kind: str  # "json" | "text" | "empty"
    auth_required: str
    doc: list[str]


@dataclass
class TokenFlow:
    """How to obtain credentials by calling an observed endpoint."""

    method: str
    path: str
    body_kind: str  # "json" | "form"
    template: Any  # body with markers: "{{username}}", "{{password}}", "{{refresh_token}}", "{{secret:NAME}}"
    access_token_path: list[str] | None
    refresh_token_path: list[str] | None
    expires_in_path: list[str] | None
    secret_params: list[str]
    evidence: list[int]


@dataclass
class AuthSpec:
    kind: str = "none"  # bearer | header | cookie | query | basic | none
    header_name: str | None = None
    scheme: str | None = None
    query_name: str | None = None
    cookie_names: list[str] = field(default_factory=list)
    extra_headers: list[str] = field(default_factory=list)  # other credential headers (e.g. CSRF)
    login: TokenFlow | None = None
    refresh: TokenFlow | None = None
    lifetime_seconds: float | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class ClientSpec:
    origin: str
    title: str
    class_name: str
    env_prefix: str
    flow_count: int
    operations: list[Operation]
    auth: AuthSpec


def _template_from_body(body: str | None, content_type: str, kinds: dict[str, str]) -> tuple[Any, list[str]]:
    """Replace secret placeholders in a redacted body with semantic markers."""
    secret_params: list[str] = []

    def marker(field_path: str, value: str) -> str:
        kind = kinds.get(field_path)
        if kind in {"username", "password", "refresh_token"}:
            return "{{" + kind + "}}"
        name = snake(field_path.rsplit(".", 1)[-1].split(":", 1)[-1])
        if name not in secret_params:
            secret_params.append(name)
        return "{{secret:" + name + "}}"

    if is_form_type(content_type):
        out = {}
        for k, v in parse_qsl(body or "", keep_blank_values=True):
            out[k] = marker(f"form:{k}", v) if PLACEHOLDER_RE.search(v) else v
        return out, secret_params
    data = parse_json(body)

    def walk(o: Any, path: str) -> Any:
        if isinstance(o, dict):
            return {k: walk(v, f"{path}.{k}") for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v, path + "[]") for v in o]
        if isinstance(o, str) and PLACEHOLDER_RE.search(o):
            return marker(f"body:{path}", o)
        return o

    return walk(data, "$"), secret_params


def _token_flow(analysis: Analysis, item: dict[str, Any], access_locations: set[str]) -> TokenFlow | None:
    if not item.get("successful_flows"):
        return None
    ctx = analysis.ctx
    flow = ctx.flows[item["successful_flows"][-1]]
    kinds = {s.location: ctx.kind(s.ref) for s in ctx.by_flow.get(flow.id, []) if s.side == "request"}
    body_kind = "form" if is_form_type(flow.req_content_type) else "json"
    template, secret_params = _template_from_body(flow.req_body, flow.req_content_type, kinds)
    issued = {s.location: ctx.kind(s.ref) for s in ctx.by_flow.get(flow.id, []) if s.side == "response"}
    access = next((loc for loc in issued if loc in access_locations), None)
    if access is None:
        access = next(
            (loc for loc, k in issued.items() if k in {"access_token", "token", "jwt", "id_token"}), None
        )
    refresh = next((loc for loc, k in issued.items() if k == "refresh_token"), None)
    access_path = location_path(access) if access else None
    expires_path = None
    if access_path:
        resp = parse_json(flow.resp_body)
        parent = resp
        for p in access_path[:-1]:
            parent = parent.get(p) if isinstance(parent, dict) else None
        if isinstance(parent, dict):
            for key in ("expires_in", "expiresIn"):
                if isinstance(parent.get(key), int | float):
                    expires_path = [*access_path[:-1], key]
    return TokenFlow(
        method=flow.method,
        path=urlsplit(flow.origin + flow.path).path,
        body_kind=body_kind,
        template=template,
        access_token_path=access_path,
        refresh_token_path=location_path(refresh) if refresh else None,
        expires_in_path=expires_path,
        secret_params=secret_params,
        evidence=item["successful_flows"][-3:],
    )


def build_auth_spec(analysis: Analysis, origin: str) -> AuthSpec:
    model = analysis.auth_for(origin)
    mechanisms = [m for m in model.get("mechanisms", []) if m.get("necessary") is not False]
    spec = AuthSpec()
    if not mechanisms:
        return spec
    primary = sorted(
        mechanisms,
        key=lambda m: (
            not m.get("necessary", False),
            MECHANISM_PRIORITY.index(m["type"]) if m["type"] in MECHANISM_PRIORITY else 99,
            -m["used_in_flows"],
        ),
    )[0]
    loc = primary["location"]
    name = loc.split(":", 1)[1]
    if primary["type"] == "cookie":
        spec.kind = "cookie"
        spec.cookie_names = [m["location"].split(":", 1)[1] for m in mechanisms if m["type"] == "cookie"]
    elif primary["type"] == "query_token":
        spec.kind, spec.query_name = "query", name
    elif primary["type"] == "basic":
        spec.kind, spec.header_name, spec.scheme = "basic", "Authorization", "Basic"
    else:
        spec.kind = "bearer" if primary["type"] == "bearer" else "header"
        spec.header_name = "Authorization" if name.lower() == "authorization" else name
        spec.scheme = primary.get("scheme") if name.lower() == "authorization" else None
    spec.extra_headers = [
        m["location"].split(":", 1)[1]
        for m in mechanisms
        if m is not primary and m["location"].startswith("header:") and m.get("necessary")
    ]
    spec.lifetime_seconds = primary.get("lifetime_seconds")
    access_locations = {i["location"] for i in primary.get("issued_by", [])}
    for item in model.get("login", []):
        spec.login = spec.login or _token_flow(analysis, item, access_locations)
    for item in model.get("refresh", []):
        spec.refresh = spec.refresh or _token_flow(analysis, item, access_locations)
    spec.notes = model.get("notes", [])
    return spec


def _py_ident_ok(name: str) -> bool:
    return name.isidentifier()


def _op_name(ep: Endpoint, prefix_len: int) -> str:
    segs = [s for s in ep.path_template.split("/") if s][prefix_len:]
    words: list[str] = []
    for seg in segs:
        if seg.startswith("{"):
            if words:
                words[-1] = singular(words[-1]) or words[-1]
            continue
        words.append(snake(seg))
    ends_with_param = bool(segs) and segs[-1].startswith("{")
    verb = VERBS.get(ep.method, ep.method.lower())
    if ep.method == "POST" and ends_with_param:
        verb = "post"
    if ep.method == "POST" and words and not ends_with_param:
        words[-1] = singular(words[-1]) or words[-1]
    if ep.method == "GET" and not ends_with_param and words:
        verb = "list" if words[-1].endswith("s") else "get"
    return "_".join([verb, *[w for w in words if w]]) or verb


def _common_prefix(endpoints: list[Endpoint]) -> int:
    paths = [[s for s in e.path_template.split("/") if s] for e in endpoints]
    if len(paths) < 2:
        return 0
    n = 0
    for parts in zip(*paths, strict=False):
        if len(set(parts)) == 1 and not parts[0].startswith("{"):
            n += 1
        else:
            break
    return min(n, min(len(p) for p in paths) - 1)


def build_spec(
    analysis: Analysis,
    origin: str,
    endpoint_ids: list[str] | None = None,
    class_name: str | None = None,
    flow_count: int = 0,
) -> ClientSpec:
    host = urlsplit(origin).hostname or "api"
    base_name = re.sub(r"^(www|api)\.", "", host).split(".")[0]
    if re.fullmatch(r"[\d.]+|localhost", host):
        base_name = "local_api"
    title = pascal(base_name)
    endpoints = analysis.catalog.for_origin(origin)
    if endpoint_ids:
        wanted = {analysis.endpoint(e).id for e in endpoint_ids}
        endpoints = [e for e in endpoints if e.id in wanted]
    auth = build_auth_spec(analysis, origin)
    skip_tags = {"login", "refresh"}
    endpoints = [e for e in endpoints if not set(e.tags) & skip_tags]
    prefix = _common_prefix(endpoints)
    ops: list[Operation] = []
    used: dict[str, int] = {}
    for ep in endpoints:
        name = _op_name(ep, prefix)
        if name in used:
            used[name] += 1
            name = (
                f"{name}_{ep.method.lower()}"
                if f"{name}_{ep.method.lower()}" not in used
                else f"{name}_{used[name]}"
            )
        used.setdefault(name, 1)
        ops.append(_operation(ep, name))
    return ClientSpec(
        origin=origin,
        title=title,
        class_name=class_name or f"{title}Client",
        env_prefix=snake(base_name).upper(),
        flow_count=flow_count,
        operations=ops,
        auth=auth,
    )


def _operation(ep: Endpoint, name: str) -> Operation:
    path_params = [
        Param(name=snake(p["name"]), wire=p["name"], type=p["type"], examples=p["examples"])
        for p in ep.path_params
    ]
    taken = {p.name for p in path_params} | {"body", "self"}
    query_params = []
    for wire, q in ep.query_params.items():
        if q["secret"]:
            continue  # credentials in the query string are handled by the auth layer
        ident = snake(wire)
        while ident in taken:
            ident += "_"
        taken.add(ident)
        query_params.append(
            Param(
                name=ident,
                wire=wire,
                type=q["type"],
                required=q["required"] and q["seen_in"] > 1,
                examples=q["examples"],
                note=f"seen in {q['seen_in']}/{len(ep.flow_ids)} requests",
            )
        )
    body_kind = None
    if ep.request_content_types:
        body_kind = (
            "form"
            if media_type(ep.request_content_types[0]) == "application/x-www-form-urlencoded"
            else "json"
        )
    success = [s for s in ep.success_statuses()]
    status = str(success[0]) if success else None
    resp = ep.responses.get(status, {}) if status else {}
    schema = resp.get("schema") or {}
    resp_kind = (
        "json" if schema else ("empty" if status == "204" or not resp.get("content_types") else "text")
    )
    doc = [f"{ep.method} {ep.path_template}", ""]
    flows = ep.flow_ids
    doc.append(
        f"Evidence: {len(flows)} observed flow(s) ({', '.join('#' + str(f) for f in flows[:5])}"
        f"{', ...' if len(flows) > 5 else ''}); responses: "
        + ", ".join(f"{s} x{r['count']}" for s, r in sorted(ep.responses.items()))
        + "."
    )
    if ep.auth:
        doc.append(f"Auth: {ep.auth.get('required', 'unknown')} -- {ep.auth.get('evidence', '')}.")
    if not ep.read_only:
        doc.append(f"Side effects: {ep.read_only_reason}.")
    for p in path_params:
        if p.examples:
            doc.append(f"{p.name}: observed values {', '.join(json.dumps(x) for x in p.examples)}.")
    for q in query_params:
        doc.append(
            f"{q.name}: query '{q.wire}', {q.note}"
            + (f"; e.g. {', '.join(json.dumps(x) for x in q.examples)}" if q.examples else "")
            + "."
        )
    return Operation(
        name=name,
        method=ep.method,
        path=ep.path_template,
        endpoint_id=ep.id,
        path_params=path_params,
        query_params=query_params,
        body_kind=body_kind,
        body_schema=ep.request_schema,
        body_required=body_kind is not None,
        response_schema=schema,
        response_status=status,
        response_kind=resp_kind,
        auth_required=(ep.auth or {}).get("required", "unknown"),
        doc=doc,
    )
