# Architecture

```
src/dapi/
  models.py          RawExchange (in-memory, unredacted) and Exchange (persisted, redacted)
  redact.py          Redactor: structural, pattern and known-value redaction; secret sightings
  vault.py           Fernet vault, deterministic refs, placeholder resolve/scrub
  store.py           SQLite (WAL): flows, secrets, sightings, sessions, kv
  workspace.py       .dapi/ discovery, config (scope), ingest(), analysis cache
  capture/
    addon.py         mitmproxy addon (DapiRecorder)
    runner.py        foreground/background mitmdump management
    convert.py       mitmproxy flow / HAR -> RawExchange, import_file()
    httpx_recorder.py  RecordingTransport for Python programs
  analysis/
    catalog.py       path templating, endpoint clustering, params, schemas, read-only classification
    schema.py        JSON Schema inference/merging and a lenient conformance checker
    auth.py          AuthContext (sightings index, credential lineage) and auth model
    deps.py          data and auth dependency edges, call order
  session.py         session derivation, request replay, verify/probe/ablation, refresh/login replay
  codegen/
    spec.py          language-neutral ClientSpec (operations and AuthSpec with login/refresh templates)
    types.py         schema -> named models (deduplicated)
    python.py        httpx client
    typescript.py    fetch client
    docs.py          OpenAPI 3.1 and Markdown
  service.py         operations shared by MCP and CLI; scrubs every result
  mcp_server.py      MCP tool definitions
  cli.py             `dapi` command
```

## Core idea: sightings

Each secret occurrence becomes a **sighting** `(ref, flow_id, side, location)`. Example locations:
`header:Authorization`, `cookie:sid`, `set-cookie:sid`, `body:$.data.access_token`, `form:password`,
`query:api_key`.

Every auth conclusion is a query over sightings plus flow metadata:

- *mechanism*: request-side sightings in headers, cookies or query strings;
- *issuer*: the first response-side sighting of the same ref;
- *lineage*: the newest ref issued at the same response location on the same origin, which is how token
  rotation is followed;
- *requirement*: whether requests without any presentation sighting succeeded or were rejected;
- *necessity*: ablation results stored in `kv["ablation:<origin>"]`.

## Extension points

- **New capture sources.** Produce `RawExchange` objects and call `Workspace.ingest()`. Redaction, storage
  and analysis come for free.
- **New secret rules.** Add names to `extra_secret_keys` in config, or extend `classify_key()` and
  `SENSITIVE_HEADERS` in `redact.py`.
- **New client languages.** Render a `ClientSpec` (see `codegen/python.py`) and register it in
  `codegen/__init__.py::LANGUAGES`. The spec already carries operations, typed models (via `TypeRegistry`),
  auth strategy, and login/refresh templates with JSON paths for the tokens.
- **New MCP tools.** Add a `@safe` method to `DapiService`, then a thin wrapper in `mcp_server.py`.
- **New analyses.** `dapi.analysis.analyze(ws)` returns a cached `Analysis` (catalog, AuthContext,
  auth model). Build on it and invalidate with `ws.invalidate()`.
