"""OpenAPI 3.1 and Markdown documentation, every statement tied to observed flows."""

from __future__ import annotations

import json
import re
from typing import Any

from dapi.analysis import Analysis
from dapi.codegen.spec import build_spec


def _strip_ext(schema: Any) -> Any:
    """Keep x-dapi-* hints (they are valid OpenAPI extensions) but drop empty schemas."""
    return schema or {}


def generate_openapi(analysis: Analysis, origin: str, flow_count: int = 0) -> dict[str, Any]:
    spec = build_spec(analysis, origin, flow_count=flow_count)
    auth_model = analysis.auth_for(origin)
    security_schemes: dict[str, Any] = {}
    a = spec.auth
    if a.kind == "bearer":
        security_schemes["observedAuth"] = {"type": "http", "scheme": "bearer"}
    elif a.kind == "basic":
        security_schemes["observedAuth"] = {"type": "http", "scheme": "basic"}
    elif a.kind == "header":
        security_schemes["observedAuth"] = {"type": "apiKey", "in": "header", "name": a.header_name}
    elif a.kind == "query":
        security_schemes["observedAuth"] = {"type": "apiKey", "in": "query", "name": a.query_name}
    elif a.kind == "cookie" and a.cookie_names:
        security_schemes["observedAuth"] = {"type": "apiKey", "in": "cookie", "name": a.cookie_names[0]}
    paths: dict[str, Any] = {}
    for ep in analysis.catalog.for_origin(origin):
        op: dict[str, Any] = {
            "operationId": next(
                (o.name for o in spec.operations if o.endpoint_id == ep.id), re.sub(r"\W+", "_", ep.key)
            ),
            "summary": ep.label,
            "x-dapi-endpoint-id": ep.id,
            "x-dapi-evidence-flows": ep.flow_ids[:20],
            "x-dapi-auth": ep.auth,
            "x-dapi-read-only": ep.read_only,
        }
        if ep.tags:
            op["tags"] = ep.tags
        params = [
            {
                "name": p["name"],
                "in": "path",
                "required": True,
                "schema": {"type": p["type"]},
                **(
                    {"examples": {f"observed{i}": {"value": v} for i, v in enumerate(p["examples"])}}
                    if p["examples"]
                    else {}
                ),
            }
            for p in ep.path_params
        ]
        for name, q in ep.query_params.items():
            params.append(
                {
                    "name": name,
                    "in": "query",
                    "required": q["required"],
                    "schema": {"type": q["type"]},
                    **({"x-dapi-secret": True} if q["secret"] else {}),
                }
            )
        for name, h in ep.request_headers.items():
            if h["secret"] or name.lower() == "authorization":
                continue
            params.append(
                {
                    "name": name,
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"},
                    **({"example": h["examples"][0]} if h["examples"] else {}),
                }
            )
        if params:
            op["parameters"] = params
        if ep.request_content_types:
            op["requestBody"] = {
                "content": {ct: {"schema": _strip_ext(ep.request_schema)} for ct in ep.request_content_types},
            }
        responses: dict[str, Any] = {}
        for status, r in ep.responses.items():
            code = status.split("-")[0]
            key = code if code.isdigit() else "default"
            entry: dict[str, Any] = {
                "description": f"Observed {r['count']} time(s)",
                "x-dapi-evidence-flows": r["flow_ids"],
            }
            if r["content_types"]:
                entry["content"] = {
                    ct: ({"schema": r["schema"]} if r["schema"] and "json" in ct else {})
                    for ct in r["content_types"]
                }
            if status.endswith("-errors"):
                entry["description"] += " with a GraphQL errors-only payload"
            if key in responses:  # e.g. GraphQL 200 data vs. 200 errors-only
                responses[key].setdefault("x-dapi-variants", []).append(entry)
            else:
                responses[key] = entry
        op["responses"] = responses or {"default": {"description": "No response observed"}}
        if security_schemes and ep.auth.get("required") in ("yes", "likely"):
            op["security"] = [{"observedAuth": []}]
        elif ep.auth.get("required") == "no":
            op["security"] = []
        if ep.graphql:
            # one OpenAPI path entry per GraphQL operation (they share the HTTP endpoint)
            op["x-dapi-graphql"] = ep.graphql
            path_key = f"{ep.path_template}#{ep.graphql['operation_name']}"
        else:
            path_key = ep.path_template
        paths.setdefault(path_key, {})[ep.method.lower()] = op
    doc: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {
            "title": f"{spec.title} API (reverse engineered)",
            "version": "observed",
            "description": "Generated by dapi from captured traffic. Schemas are inferred from observed samples "
            "and may be incomplete. x-dapi-evidence-flows reference flow ids in the dapi workspace.",
        },
        "servers": [{"url": origin}],
        "paths": paths,
        "x-dapi-auth-notes": auth_model.get("notes", []),
    }
    if security_schemes:
        doc["components"] = {"securitySchemes": security_schemes}
    return doc


def generate_markdown(analysis: Analysis, origin: str, flow_count: int = 0) -> str:
    spec = build_spec(analysis, origin, flow_count=flow_count)
    auth = analysis.auth_for(origin)
    lines = [f"# {spec.title} API (reverse engineered from {origin})", ""]
    lines.append(
        "Generated by dapi from captured traffic. Flow ids (`#12`) refer to evidence in the dapi workspace; "
        "inspect them with the `traffic_get` MCP tool or `dapi flows show <id>`."
    )
    lines += ["", "## Authentication", ""]
    a = spec.auth
    lines.append(
        f"- Client auth strategy: **{a.kind}**"
        + (f" via `{a.header_name}`" if a.header_name else "")
        + (f" (scheme `{a.scheme}`)" if a.scheme else "")
    )
    if a.login:
        lines.append(
            f"- Login: `{a.login.method} {a.login.path}` (flows {', '.join('#' + str(x) for x in a.login.evidence)})"
        )
    if a.refresh:
        lines.append(
            f"- Refresh: `{a.refresh.method} {a.refresh.path}` (flows {', '.join('#' + str(x) for x in a.refresh.evidence)})"
        )
    if a.lifetime_seconds:
        lines.append(f"- Declared token lifetime: ~{int(a.lifetime_seconds)}s")
    for note in auth.get("notes", []):
        lines.append(f"- {note}")
    lines += ["", "## Endpoints", "", "| Method | Path | Auth | Statuses | Flows |", "|---|---|---|---|---|"]
    eps = analysis.catalog.for_origin(origin)
    for ep in eps:
        statuses = ", ".join(f"{s}×{r['count']}" for s, r in sorted(ep.responses.items()))
        lines.append(
            f"| {ep.method} | `{ep.path_template}` | {ep.auth.get('required', '?')} | {statuses} | {len(ep.flow_ids)} |"
        )
    for ep in eps:
        lines += ["", f"### {ep.method} `{ep.path_template}`", ""]
        lines.append(
            f"- Endpoint id: `{ep.id}`; evidence flows: {', '.join('#' + str(f) for f in ep.flow_ids[:10])}"
        )
        lines.append(f"- Auth: {ep.auth.get('required', 'unknown')} — {ep.auth.get('evidence', '')}")
        lines.append(f"- Read-only: {'yes' if ep.read_only else 'no'} ({ep.read_only_reason})")
        if ep.path_params:
            lines.append(
                "- Path params: "
                + ", ".join(
                    f"`{p['name']}` ({p['kind']}, e.g. {', '.join(p['examples'][:2])})"
                    for p in ep.path_params
                )
            )
        if ep.query_params:
            lines.append(
                "- Query params: "
                + ", ".join(
                    f"`{k}`{' (required)' if q['required'] else ''}{' (secret)' if q['secret'] else ''}"
                    for k, q in ep.query_params.items()
                )
            )
        if ep.request_schema:
            lines += [
                "",
                "Request body schema:",
                "",
                "```json",
                json.dumps(ep.request_schema, indent=2),
                "```",
            ]
        for status, r in sorted(ep.responses.items()):
            if r["schema"]:
                lines += [
                    "",
                    f"Response `{status}` schema ({r['count']} samples):",
                    "",
                    "```json",
                    json.dumps(r["schema"], indent=2),
                    "```",
                ]
    return "\n".join(lines) + "\n"
