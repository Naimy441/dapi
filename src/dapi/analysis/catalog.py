"""Endpoint discovery: cluster observed flows into templated endpoints with inferred schemas."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote

from dapi.analysis.schema import SchemaBuilder
from dapi.models import Exchange, is_form_type, is_json_type, media_type
from dapi.vault import PLACEHOLDER_RE

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
TOKENISH_RE = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_\-]{10,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
EMAIL_RE = re.compile(r"^[^@/\s]+@[^@/\s]+\.[A-Za-z]{2,}$")
MUTATING_PATH_RE = re.compile(
    r"(?i)(log[-_]?out|sign[-_]?out|delete|remove|destroy|revoke|unsubscribe|cancel|disable|reset|deactivate|purge)"
)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
BORING_HEADERS = {
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "connection",
    "host",
    "content-length",
    "origin",
    "referer",
    "cookie",
    "cache-control",
    "pragma",
    "dnt",
    "upgrade-insecure-requests",
    "priority",
    "te",
    "if-none-match",
    "if-modified-since",
    "content-type",
    "keep-alive",
    "proxy-connection",
    "x-forwarded-for",
    "x-forwarded-proto",
    "via",
    "x-real-ip",
}
PARAM_MARK = "\x00"
MIN_DISTINCT_FOR_MERGE = 3
MAX_EXAMPLES = 3


def classify_segment(seg: str) -> str | None:
    """Return a parameter kind if a path segment looks like an identifier."""
    s = unquote(seg)
    if not s:
        return None
    if PLACEHOLDER_RE.search(s):
        return "secret"
    if s.isdigit():
        return "integer"
    if UUID_RE.match(s):
        return "uuid"
    if HEX_RE.match(s):
        return "hex"
    if DATE_RE.match(s):
        return "date"
    if EMAIL_RE.match(s):
        return "email"
    if TOKENISH_RE.match(s):
        return "token"
    return None


def singular(word: str) -> str:
    w = re.sub(r"[^A-Za-z0-9]+", "_", word).strip("_").lower()
    if w.endswith("ies") and len(w) > 4:
        return w[:-3] + "y"
    if w.endswith("sses") or w.endswith("xes"):
        return w[:-2]
    if w.endswith("s") and not w.endswith("ss") and len(w) > 3:
        return w[:-1]
    return w


def is_read_only(method: str, template: str) -> tuple[bool, str]:
    if method not in SAFE_METHODS:
        return False, f"{method} may change server state"
    if MUTATING_PATH_RE.search(template):
        return False, "path suggests a state-changing action (e.g. logout/delete)"
    return True, f"{method} with no state-changing keywords in the path"


def parse_json(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


@dataclass
class Endpoint:
    id: str
    method: str
    origin: str
    host: str
    path_template: str
    path_params: list[dict[str, Any]] = field(default_factory=list)
    query_params: dict[str, dict[str, Any]] = field(default_factory=dict)
    request_headers: dict[str, dict[str, Any]] = field(default_factory=dict)
    request_content_types: list[str] = field(default_factory=list)
    request_schema: dict[str, Any] = field(default_factory=dict)
    responses: dict[str, dict[str, Any]] = field(default_factory=dict)
    flow_ids: list[int] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    read_only: bool = False
    read_only_reason: str = ""
    auth: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method} {self.origin}{self.path_template}"

    def success_statuses(self) -> list[int]:
        return sorted(int(s) for s in self.responses if s.isdigit() and 200 <= int(s) < 300)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "origin": self.origin,
            "path": self.path_template,
            "statuses": {s: r["count"] for s, r in sorted(self.responses.items())},
            "flows": len(self.flow_ids),
            "read_only": self.read_only,
            "auth": self.auth.get("required", "unknown"),
            **({"tags": self.tags} if self.tags else {}),
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Catalog:
    endpoints: list[Endpoint]
    flow_endpoint: dict[int, str]  # flow id -> endpoint id
    flow_params: dict[int, dict[str, str]]  # flow id -> path param values

    def get(self, endpoint_id: str) -> Endpoint | None:
        for ep in self.endpoints:
            if ep.id == endpoint_id or ep.key == endpoint_id:
                return ep
        return None

    def for_origin(self, origin_or_host: str | None) -> list[Endpoint]:
        if not origin_or_host:
            return list(self.endpoints)
        needle = origin_or_host.lower().rstrip("/")
        return [
            e for e in self.endpoints if needle in (e.origin, e.host) or e.origin.endswith("://" + needle)
        ]

    def origins(self) -> list[str]:
        return sorted({e.origin for e in self.endpoints})


def _structure(value: Any, depth: int = 0) -> str:
    """Structural fingerprint: types and keys (several levels deep), not values."""
    if depth > 3:
        return "*"
    if isinstance(value, dict):
        keys = sorted(value)[:40]
        return "{" + ",".join(f"{k}:{_structure(value[k], depth + 1)}" for k in keys) + "}"
    if isinstance(value, list):
        first = next((x for x in value if x is not None), None)
        return "[" + (_structure(first, depth + 1) if first is not None else "") + "]"
    if isinstance(value, bool) or value is None:
        return "b" if isinstance(value, bool) else "n"
    return "s" if isinstance(value, str) else "d"


def _shape_signature(ex: Exchange) -> str | None:
    """Response fingerprint used to decide whether varying path segments are one parameterized endpoint.

    Deep enough that collections sharing an envelope (``{"data": [...]}``) but holding different
    records (users vs. orders) do not look alike.
    """
    if ex.status is None or not 200 <= ex.status < 300:
        return None
    data = parse_json(ex.resp_body) if is_json_type(ex.resp_content_type) or ex.resp_body else None
    if isinstance(data, dict | list):
        if isinstance(data, list) and not data:
            return None  # an empty list says nothing about the record shape
        return _structure(data)
    return "ct:" + media_type(ex.resp_content_type)


def _template_segments(flows: list[Exchange]) -> dict[int, list[str]]:
    segs: dict[int, list[str]] = {}
    for ex in flows:
        parts = ex.path.split("/")[1:] if ex.path.startswith("/") else ex.path.split("/")
        segs[ex.id] = [PARAM_MARK + kind if (kind := classify_segment(p)) else p for p in parts]

    # Cardinality merge: literal segments that vary across otherwise-identical paths and
    # return the same response shape are treated as parameters (e.g. /users/alice, /users/bob).
    by_id = {ex.id: ex for ex in flows}
    groups: dict[tuple, list[int]] = defaultdict(list)
    for ex in flows:
        groups[(ex.method, ex.origin, len(segs[ex.id]))].append(ex.id)
    for (_, _, n), ids in groups.items():
        for i in range(n):
            buckets: dict[tuple, list[int]] = defaultdict(list)
            for fid in ids:
                s = segs[fid]
                if not s[i].startswith(PARAM_MARK) and s[i]:
                    buckets[tuple(s[:i] + s[i + 1 :])].append(fid)
            for bucket_ids in buckets.values():
                values = {segs[f][i] for f in bucket_ids}
                if len(values) < MIN_DISTINCT_FOR_MERGE:
                    continue
                sigs_by_value: dict[str, set[str]] = defaultdict(set)
                for f in bucket_ids:
                    sig = _shape_signature(by_id[f])
                    if sig:
                        sigs_by_value[segs[f][i]].add(sig)
                distinct_sigs = {s for sigs in sigs_by_value.values() for s in sigs}
                if len(sigs_by_value) >= MIN_DISTINCT_FOR_MERGE and len(distinct_sigs) == 1:
                    for f in bucket_ids:
                        segs[f][i] = PARAM_MARK + "string"
    return segs


def _name_params(segments: list[str]) -> tuple[str, list[dict[str, Any]]]:
    parts, params, used = [], [], Counter()
    for i, seg in enumerate(segments):
        if not seg.startswith(PARAM_MARK):
            parts.append(seg)
            continue
        kind = seg[1:]
        prev = segments[i - 1] if i > 0 and not segments[i - 1].startswith(PARAM_MARK) else ""
        base = singular(prev) if prev and re.search(r"[A-Za-z]", prev) else "param"
        if kind in {"integer", "uuid", "hex", "token"} or base == "param":
            base = f"{base}_id" if base != "param" else "param"
        if not re.match(r"^[A-Za-z_]", base):
            base = "p_" + base
        used[base] += 1
        name = base if used[base] == 1 else f"{base}{used[base]}"
        params.append({"name": name, "kind": kind, "position": i})
        parts.append("{" + name + "}")
    return "/" + "/".join(parts), params


def _value_type(values: list[str]) -> str:
    if values and all(v.lstrip("-").isdigit() for v in values):
        return "integer"
    if values and all(v.lower() in {"true", "false"} for v in values):
        return "boolean"
    return "string"


def build_catalog(flows: list[Exchange]) -> Catalog:
    flows = [ex for ex in flows if ex.id is not None]
    segs = _template_segments(flows)
    grouped: dict[tuple[str, str, str], list[Exchange]] = defaultdict(list)
    templates: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for ex in flows:
        template, params = _name_params(segs[ex.id])
        key = (ex.method, ex.origin, template)
        grouped[key].append(ex)
        templates[key] = params

    endpoints: list[Endpoint] = []
    flow_endpoint: dict[int, str] = {}
    flow_params: dict[int, dict[str, str]] = {}
    for (method, origin, template), exs in grouped.items():
        ep_id = "e_" + hashlib.sha1(f"{method} {origin}{template}".encode()).hexdigest()[:8]
        ro, reason = is_read_only(method, template)
        ep = Endpoint(
            id=ep_id,
            method=method,
            origin=origin,
            host=exs[0].host,
            path_template=template,
            flow_ids=[e.id for e in exs],
            first_seen=min(e.ts for e in exs),
            last_seen=max(e.ts for e in exs),
            read_only=ro,
            read_only_reason=reason,
        )
        # path params
        params = templates[(method, origin, template)]
        examples: dict[str, list[str]] = defaultdict(list)
        for ex in exs:
            raw_parts = ex.path.split("/")[1:]
            values = {}
            for p in params:
                if p["position"] < len(raw_parts):
                    v = unquote(raw_parts[p["position"]])
                    values[p["name"]] = v
                    if v not in examples[p["name"]] and not PLACEHOLDER_RE.search(v):
                        examples[p["name"]].append(v)
            flow_params[ex.id] = values
            flow_endpoint[ex.id] = ep_id
        ep.path_params = [
            {
                "name": p["name"],
                "kind": p["kind"],
                "type": "integer" if p["kind"] == "integer" else "string",
                "examples": examples[p["name"]][:MAX_EXAMPLES],
            }
            for p in params
        ]
        # query params
        q_values: dict[str, list[str]] = defaultdict(list)
        q_counts: Counter[str] = Counter()
        for ex in exs:
            for name in {k for k, _ in ex.query}:
                q_counts[name] += 1
            for k, v in ex.query:
                q_values[k].append(v)
        for name, count in q_counts.items():
            vals = q_values[name]
            secret = any(PLACEHOLDER_RE.search(v) for v in vals)
            plain = [v for v in dict.fromkeys(vals) if not PLACEHOLDER_RE.search(v)]
            ep.query_params[name] = {
                "required": count == len(exs),
                "seen_in": count,
                "type": _value_type(plain),
                "secret": secret,
                "examples": plain[:MAX_EXAMPLES],
            }
        # notable request headers
        h_counts: Counter[str] = Counter()
        h_examples: dict[str, list[str]] = defaultdict(list)
        for ex in exs:
            for name, value in ex.req_headers:
                lname = name.lower()
                if lname in BORING_HEADERS or lname.startswith(("sec-", ":")):
                    continue
                h_counts[name] += 1
                if value not in h_examples[name]:
                    h_examples[name].append(value)
        for name, count in h_counts.items():
            vals = h_examples[name]
            secret = any(PLACEHOLDER_RE.search(v) for v in vals)
            ep.request_headers[name] = {
                "seen_in": count,
                "secret": secret,
                "examples": [] if secret else vals[:MAX_EXAMPLES],
            }
        # request body
        req_builder = SchemaBuilder()
        cts: list[str] = []
        for ex in exs:
            if not ex.req_body:
                continue
            ct = media_type(ex.req_content_type)
            if ct and ct not in cts:
                cts.append(ct)
            if is_json_type(ex.req_content_type):
                data = parse_json(ex.req_body)
                if data is not None:
                    req_builder.add(data)
            elif is_form_type(ex.req_content_type):
                req_builder.add(dict(parse_qsl(ex.req_body, keep_blank_values=True)))
        ep.request_content_types = cts
        ep.request_schema = req_builder.schema()
        # responses
        by_status: dict[str, list[Exchange]] = defaultdict(list)
        for ex in exs:
            by_status[str(ex.status) if ex.status is not None else "error"].append(ex)
        for status, sexs in sorted(by_status.items()):
            builder = SchemaBuilder()
            r_cts: list[str] = []
            for ex in sexs:
                ct = media_type(ex.resp_content_type)
                if ct and ct not in r_cts:
                    r_cts.append(ct)
                if is_json_type(ex.resp_content_type) or (ex.resp_body or "").lstrip()[:1] in ("{", "["):
                    data = parse_json(ex.resp_body)
                    if data is not None:
                        builder.add(data)
            ep.responses[status] = {
                "count": len(sexs),
                "content_types": r_cts,
                "schema": builder.schema(),
                "flow_ids": [e.id for e in sexs][-5:],
            }
        endpoints.append(ep)

    endpoints.sort(key=lambda e: (e.origin, e.path_template, e.method))
    return Catalog(endpoints, flow_endpoint, flow_params)
