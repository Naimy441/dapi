"""MCP server exposing dapi to AI agents (Claude Code, Codex, Cursor, ...).

Run with ``dapi mcp`` (stdio). All tool results are scrubbed: credentials are
represented by ``{{secret:s_...}}`` references and never revealed.
"""

from __future__ import annotations

import functools
from typing import Annotated, Any

import anyio
from pydantic import Field

from dapi import __version__
from dapi.service import DapiService
from dapi.workspace import Workspace

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]
from mcp.types import ToolAnnotations

INSTRUCTIONS = """\
dapi reverse-engineers HTTP APIs from traffic the user is authorized to inspect.

Typical workflow:
1. dapi_status -> see what is captured. If nothing: capture_start (then ask the user to use the app through
   the proxy) or traffic_import a HAR file. capture_stop when done.
2. endpoints_discover -> endpoint catalog (ids like e_1a2b3c4d). endpoint_get / schema_infer for details.
3. auth_analyze -> how credentials are issued (login/refresh), presented (header/cookie), and expire.
4. session_verify(probe_auth=true) -> proves the captured session works against read-only endpoints,
   auto-refreshes expired tokens, and tests which credentials are actually required.
5. dependencies_discover -> which responses feed which requests (call order).
6. client_generate(language="python"|"typescript") -> typed client; docs_generate -> OpenAPI/Markdown.

Rules: credentials appear only as {{secret:s_...}} references; never ask the user to paste secrets into the chat
(use the `dapi creds` / `dapi session set` CLI instead). Ground every claim in flow ids (#12) returned by the tools.
session_verify only sends GET/HEAD requests to endpoints that look read-only; login replay requires allow_login=true.
"""

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
LOCAL_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
NETWORK = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)

Origin = Annotated[
    str | None,
    Field(
        description="Origin or host, e.g. https://api.example.com or api.example.com. Optional if only one origin was captured."
    ),
]
EndpointId = Annotated[str, Field(description="Endpoint id from endpoints_discover (e.g. e_1a2b3c4d)")]


def build_server(workspace: Workspace | None = None) -> Any:
    svc = DapiService(workspace)
    server = _Server(name="dapi", instructions=INSTRUCTIONS)

    async def call(fn, *args: Any, **kwargs: Any) -> Any:
        return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))

    @server.tool(annotations=READ)
    async def dapi_status() -> dict[str, Any]:
        """Overview of the workspace: captured origins, flow and endpoint counts, capture state, next steps."""
        return await call(svc.status)

    @server.tool(annotations=NETWORK)
    async def capture_start(
        port: Annotated[int, Field(description="Proxy listen port")] = 8080,
        scope: Annotated[
            list[str] | None,
            Field(description="Host globs to record, e.g. ['api.example.com', '*.example.com']"),
        ] = None,
        mode: Annotated[
            str | None,
            Field(
                description="mitmproxy mode: regular (default), wireguard, reverse:https://host, upstream:http://proxy, local"
            ),
        ] = None,
        listen_host: Annotated[
            str, Field(description="Use 0.0.0.0 to accept traffic from a phone on the LAN")
        ] = "127.0.0.1",
    ) -> dict[str, Any]:
        """Start a background mitmproxy that records (redacted) traffic into the workspace.
        Returns the proxy URL and instructions for routing a browser, CLI, or mobile app through it."""
        return await call(svc.capture_start, port, scope, mode, listen_host)

    @server.tool(annotations=LOCAL_WRITE)
    async def capture_stop() -> dict[str, Any]:
        """Stop the background capture proxy."""
        return await call(svc.capture_stop)

    @server.tool(annotations=LOCAL_WRITE)
    async def traffic_import(
        path: Annotated[str, Field(description="Path to a .har file or a mitmproxy flow dump")],
    ) -> dict[str, Any]:
        """Import traffic from a HAR file (browser DevTools, Charles, Proxyman) or a mitmproxy .flow/.mitm dump."""
        return await call(svc.traffic_import, path)

    @server.tool(annotations=LOCAL_WRITE)
    async def scope_set(
        hosts: Annotated[list[str], Field(description="Host globs that may be recorded and verified")],
        ignore_hosts: Annotated[
            list[str] | None, Field(description="Host globs to never record (telemetry, CDNs)")
        ] = None,
    ) -> dict[str, Any]:
        """Restrict which hosts are recorded and which may be contacted by session_verify."""
        return await call(svc.scope_set, hosts, ignore_hosts)

    @server.tool(annotations=READ)
    async def traffic_list(
        origin: Origin = None,
        method: str | None = None,
        path_contains: str | None = None,
        status: int | None = None,
        endpoint_id: Annotated[str | None, Field(description="Only flows belonging to this endpoint")] = None,
        source: Annotated[
            str | None, Field(description="mitmproxy, har, dapi-verify, dapi-probe, dapi-refresh, ...")
        ] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List captured flows (redacted summaries) with optional filters."""
        return await call(
            svc.traffic_list, origin, method, path_contains, status, endpoint_id, source, limit, offset
        )

    @server.tool(annotations=READ)
    async def traffic_get(
        flow_id: int,
        max_body_chars: Annotated[
            int, Field(description="Truncate bodies beyond this many characters")
        ] = 4000,
    ) -> dict[str, Any]:
        """Full redacted request/response for one flow, plus where secrets appeared (refs and locations)."""
        return await call(svc.traffic_get, flow_id, max_body_chars)

    @server.tool(annotations=READ)
    async def traffic_search(text: str, limit: int = 30) -> dict[str, Any]:
        """Case-insensitive search across URLs, headers and bodies of captured flows."""
        return await call(svc.traffic_search, text, limit)

    @server.tool(annotations=READ)
    async def endpoints_discover(origin: Origin = None) -> dict[str, Any]:
        """Cluster flows into templated endpoints (e.g. GET /users/{user_id}) with status counts,
        read-only classification and inferred auth requirement."""
        return await call(svc.endpoints_discover, origin)

    @server.tool(annotations=READ)
    async def endpoint_get(endpoint_id: EndpointId) -> dict[str, Any]:
        """Everything known about one endpoint: params, headers, request/response schemas per status,
        auth evidence, dependencies and evidence flow ids."""
        return await call(svc.endpoint_get, endpoint_id)

    @server.tool(annotations=READ)
    async def schema_infer(
        endpoint_id: EndpointId,
        part: Annotated[str, Field(description="'response' or 'request'")] = "response",
        status: Annotated[
            str | None, Field(description="Response status code; defaults to the first 2xx")
        ] = None,
    ) -> dict[str, Any]:
        """JSON Schema inferred from every observed sample of an endpoint's request or response."""
        return await call(svc.schema_infer, endpoint_id, part, status)

    @server.tool(annotations=READ)
    async def auth_analyze(origin: Origin = None) -> dict[str, Any]:
        """Map authentication: credential mechanisms (bearer/cookie/api key), which endpoint issues each credential,
        login and refresh endpoints, token lifetimes, CSRF pairing, reactive refresh patterns, per-endpoint requirements."""
        return await call(svc.auth_analyze, origin)

    @server.tool(annotations=READ)
    async def dependencies_discover(endpoint_id: str | None = None, origin: Origin = None) -> dict[str, Any]:
        """Data and auth dependencies between endpoints (values returned by one request and sent in a later one),
        plus a suggested call order."""
        return await call(svc.dependencies_discover, endpoint_id, origin)

    @server.tool(annotations=NETWORK)
    async def session_verify(
        origin: Origin = None,
        endpoint_ids: Annotated[
            list[str] | None, Field(description="Specific read-only endpoints to check")
        ] = None,
        probe_auth: Annotated[
            bool,
            Field(
                description="Also send each request without credentials, and test which credentials are required"
            ),
        ] = False,
        refresh_if_needed: Annotated[
            bool, Field(description="Replay the observed refresh flow on 401/403")
        ] = True,
        allow_login: Annotated[
            bool, Field(description="Permit replaying the observed login (uses vaulted username/password)")
        ] = False,
        max_endpoints: int = 3,
    ) -> dict[str, Any]:
        """Verify the captured session programmatically by calling read-only (GET/HEAD) endpoints with vaulted
        credentials; compares status and response shape with observations. Requests are recorded as evidence."""
        return await call(
            svc.session_verify,
            origin,
            endpoint_ids,
            probe_auth,
            refresh_if_needed,
            allow_login,
            max_endpoints,
        )

    @server.tool(annotations=NETWORK)
    async def session_refresh(origin: Origin = None, allow_login: bool = False) -> dict[str, Any]:
        """Obtain fresh credentials by replaying the observed refresh flow (or login flow if allow_login)."""
        return await call(svc.session_refresh, origin, allow_login)

    @server.tool(annotations=READ)
    async def credentials_list(origin: Origin = None) -> dict[str, Any]:
        """Vaulted credentials as metadata only (ref, kind, where seen, JWT timing claims, expiry). Never values."""
        return await call(svc.credentials_list, origin)

    @server.tool(annotations=LOCAL_WRITE)
    async def client_generate(
        origin: Origin = None,
        language: Annotated[str, Field(description="'python' or 'typescript'")] = "python",
        output_dir: Annotated[
            str | None,
            Field(description="Directory to write the client to (default ./dapi_generated/clients)"),
        ] = None,
        endpoint_ids: Annotated[list[str] | None, Field(description="Limit to these endpoints")] = None,
        class_name: str | None = None,
    ) -> dict[str, Any]:
        """Generate a typed API client (httpx for Python, fetch for TypeScript) with observed auth handling
        (login, refresh, retry on 401) and one documented method per endpoint citing evidence flows."""
        return await call(svc.client_generate, origin, language, output_dir, endpoint_ids, class_name)

    @server.tool(annotations=LOCAL_WRITE)
    async def docs_generate(
        origin: Origin = None,
        format: Annotated[str, Field(description="'openapi' (3.1 JSON) or 'markdown'")] = "openapi",
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Write OpenAPI 3.1 or Markdown documentation with x-dapi evidence annotations."""
        return await call(svc.docs_generate, origin, format, output_path)

    @server.prompt()
    def reverse_engineer(target: str = "the app") -> str:
        """Guided workflow for reverse engineering an API with dapi."""
        return (
            f"Reverse engineer the HTTP API used by {target} with the dapi tools. Start with dapi_status. "
            "If no traffic exists, start a capture (scoped to the app's API hosts) and ask me to exercise the app, "
            "including logging in. Then: endpoints_discover, auth_analyze, session_verify with probe_auth=true, "
            "dependencies_discover, and client_generate. Summarize the auth flow and the endpoint catalog, citing "
            "flow ids for every claim. Never ask me to paste credentials into the chat."
        )

    return server


def main(workspace: Workspace | None = None) -> None:
    build_server(workspace).run()


__all__ = ["build_server", "main", "__version__"]
