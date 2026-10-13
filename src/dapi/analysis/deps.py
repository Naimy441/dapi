"""Endpoint dependency discovery.

Two kinds of edges, both derived from observed values:

* ``data``: a value returned by endpoint A (e.g. ``$.items[].id``) is later sent
  to endpoint B (as a path parameter, query parameter or body field).
* ``auth``: a credential issued by endpoint A is later presented to endpoint B.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import parse_qsl

from dapi.analysis.auth import AuthContext
from dapi.analysis.catalog import parse_json
from dapi.models import Exchange, is_form_type
from dapi.vault import PLACEHOLDER_RE

MAX_VALUES_PER_RESPONSE = 2000


def _distinctive(key: str, value: Any) -> str | None:
    """Return a canonical string for values specific enough to link requests, else None."""
    if isinstance(value, bool) or value is None:
        return None
    k = key.lower()
    idish = k == "id" or k.endswith(("id", "_id", "ids", "uuid", "key", "slug", "handle", "cursor", "token"))
    if isinstance(value, int):
        return str(value) if (idish and abs(value) >= 1) or abs(value) >= 100000 else None
    if isinstance(value, str):
        if PLACEHOLDER_RE.search(value) or len(value) > 200:
            return None
        if len(value) >= 8 or (idish and len(value) >= 2):
            return value
    return None


def _walk(obj: Any, path: str, out: list[tuple[str, str]], key: str = "") -> None:
    if len(out) > MAX_VALUES_PER_RESPONSE:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk(v, f"{path}.{k}", out, str(k))
    elif isinstance(obj, list):
        for v in obj[:200]:
            _walk(v, path + "[]", out, key)
    else:
        canon = _distinctive(key, obj)
        if canon is not None:
            out.append((canon, path))


def _request_values(ex: Exchange, path_params: dict[str, str]) -> list[tuple[str, str]]:
    vals: list[tuple[str, str]] = [(v, f"path:{name}") for name, v in path_params.items()]
    vals += [(v, f"query:{k}") for k, v in ex.query if v and not PLACEHOLDER_RE.search(v)]
    if ex.req_body:
        if is_form_type(ex.req_content_type):
            vals += [
                (v, f"form:{k}") for k, v in parse_qsl(ex.req_body) if v and not PLACEHOLDER_RE.search(v)
            ]
        else:
            data = parse_json(ex.req_body)
            if data is not None:
                found: list[tuple[str, str]] = []
                _walk(data, "$", found)
                vals += [(v, f"body:{p}") for v, p in found]
    return vals


def discover_dependencies(
    ctx: AuthContext, endpoint_id: str | None = None, origin: str | None = None
) -> dict[str, Any]:
    flows = sorted(ctx.flows.values(), key=lambda f: (f.ts, f.id))
    if origin:
        allowed = {e.id for e in ctx.catalog.for_origin(origin)}
    else:
        allowed = {e.id for e in ctx.catalog.endpoints}
    produced: dict[
        str, tuple[str, str, int]
    ] = {}  # value -> (endpoint id, json path, flow id), first producer
    edges: dict[tuple, dict[str, Any]] = {}

    for ex in flows:
        ep_id = ctx.catalog.flow_endpoint.get(ex.id)
        if ep_id is None:
            continue
        # consume first (a request can only depend on earlier responses)
        if ep_id in allowed:
            for value, location in _request_values(ex, ctx.catalog.flow_params.get(ex.id, {})):
                src = produced.get(value)
                if src is None or src[0] == ep_id and location.startswith("path:"):
                    continue
                key = ("data", src[0], src[1], ep_id, location)
                edge = edges.setdefault(
                    key,
                    {
                        "type": "data",
                        "from": src[0],
                        "from_field": src[1],
                        "to": ep_id,
                        "to_field": location,
                        "observations": 0,
                        "example_flows": [],
                    },
                )
                edge["observations"] += 1
                if len(edge["example_flows"]) < 3:
                    edge["example_flows"].append([src[2], ex.id])
        if ex.status and 200 <= ex.status < 300:
            data = parse_json(ex.resp_body)
            if data is not None:
                found: list[tuple[str, str]] = []
                _walk(data, "$", found)
                for value, path in found:
                    produced.setdefault(value, (ep_id, path, ex.id))

    # auth edges from secret lineage
    for ex in flows:
        ep_id = ctx.catalog.flow_endpoint.get(ex.id)
        if ep_id not in allowed:
            continue
        for s in ctx.presentations(ex.id):
            first = ctx.issue(s.ref)
            if first is None or first.flow_id == ex.id:
                continue
            src_ep = ctx.catalog.flow_endpoint.get(first.flow_id)
            if not src_ep or src_ep == ep_id:
                continue
            key = ("auth", src_ep, first.location, ep_id, s.location)
            edge = edges.setdefault(
                key,
                {
                    "type": "auth",
                    "from": src_ep,
                    "from_field": first.location,
                    "to": ep_id,
                    "to_field": s.location,
                    "observations": 0,
                    "example_flows": [],
                },
            )
            edge["observations"] += 1
            if len(edge["example_flows"]) < 3:
                edge["example_flows"].append([first.flow_id, ex.id])

    result = list(edges.values())
    if endpoint_id:
        ep = ctx.catalog.get(endpoint_id)
        target = ep.id if ep else endpoint_id
        result = [e for e in result if e["to"] == target or e["from"] == target]
    names = {e.id: e.label for e in ctx.catalog.endpoints}
    for e in result:
        e["from_endpoint"] = names.get(e["from"], e["from"])
        e["to_endpoint"] = names.get(e["to"], e["to"])
    result.sort(key=lambda e: (e["type"], -e["observations"]))

    prereqs: dict[str, set[str]] = defaultdict(set)
    for e in result:
        prereqs[e["to"]].add(e["from"])
    return {
        "edges": result,
        "prerequisites": {names.get(k, k): sorted(names.get(x, x) for x in v) for k, v in prereqs.items()},
        "call_order": _call_order(prereqs, names),
    }


def _call_order(prereqs: dict[str, set[str]], names: dict[str, str]) -> list[str]:
    """Topological order of endpoints that participate in dependencies (cycles broken arbitrarily)."""
    nodes = set(prereqs) | {p for ps in prereqs.values() for p in ps}
    order, visiting, done = [], set(), set()

    def visit(n: str) -> None:
        if n in done or n in visiting:
            return
        visiting.add(n)
        for p in sorted(prereqs.get(n, ())):
            visit(p)
        visiting.discard(n)
        done.add(n)
        order.append(names.get(n, n))

    for n in sorted(nodes):
        visit(n)
    return order
