# dapi

**Evidence-grounded API reverse engineering for AI agents.** dapi records the traffic of a web or mobile app
you are authorized to inspect (via [mitmproxy](https://mitmproxy.org) or a HAR file). From that traffic it:

- builds an **API catalog** of templated endpoints, parameters and inferred JSON Schemas;
- **maps authentication**: logins, cookies, bearer tokens, API keys, expiry and refresh/rotation;
- **verifies sessions** programmatically against read-only endpoints;
- discovers **endpoint dependencies**;
- generates working **Python and TypeScript clients**.

All of it is exposed to Claude Code, Codex, Cursor and any other MCP client through an
[MCP](https://modelcontextprotocol.io) server.

Credentials never reach the model. dapi moves every secret into an encrypted vault as soon as it is
captured. Everything the model sees uses opaque references like `{{secret:s_3fa9c01b2d}}`. Every claim in
the catalog, the docs and the generated code cites the captured flows (`#12`) it came from.

```text
 app / browser / phone ──► mitmproxy + dapi recorder ──► redactor ──► SQLite (redacted flows)
                                                             │               │
                                                             ▼               ▼
                                                    encrypted vault ◄── analysis: catalog · auth · deps
                                                             │               │
                                     session verify / refresh ◄──────────────┤
                                                                             ▼
                                         MCP tools · CLI · Python/TS clients · OpenAPI · Markdown
```

> **Use dapi only on applications and accounts you own or are explicitly authorized to test.** It is a
> tool for building integrations, debugging and security research within scope, not for bypassing
> access controls.

## Quickstart (5 minutes, no app needed)

```bash
pip install git+https://github.com/naimy441/dapi   # or: uv tool install git+https://github.com/naimy441/dapi
git clone https://github.com/naimy441/dapi && cd dapi   # for the demo API

python examples/demo_api.py --port 8765 &          # a small API with login + rotating refresh tokens
dapi init --scope 127.0.0.1
dapi capture --port 8080 &                          # recording proxy

# use the "app" through the proxy (any HTTP client works; this is what a real app would do)
export http_proxy=http://127.0.0.1:8080   # lowercase: curl ignores HTTP_PROXY for http:// URLs
curl -s -X POST 127.0.0.1:8765/api/v1/auth/login -H 'content-type: application/json' \
     -d '{"username":"demo","password":"demo-password"}' | tee /tmp/login.json
TOKEN=$(python -c 'import json;print(json.load(open("/tmp/login.json"))["access_token"])')
for p in me projects projects/101 projects/101/tasks; do
  curl -s 127.0.0.1:8765/api/v1/$p -H "Authorization: Bearer $TOKEN" >/dev/null; done
unset http_proxy; kill %2

dapi endpoints                      # catalog
dapi auth                           # how auth works, with evidence
dapi verify --probe-auth            # does the session work? which credentials are actually required?
dapi generate --lang python         # -> dapi_generated/clients/local_api_client.py
```

```python
from local_api_client import LocalApiClient

client = LocalApiClient.from_dapi()  # reuse the captured session, no manual login
print(client.list_projects()["items"])
client = LocalApiClient(username="demo", password="demo-password")
client.login()
print(client.get_project(101))  # auto-refreshes on 401 via the observed refresh flow
```

## Use it from an AI agent

```bash
dapi mcp-config --client claude    # prints: claude mcp add dapi -- dapi mcp
dapi mcp-config --client codex     # prints a ~/.codex/config.toml snippet
dapi mcp-config --client json      # generic {"mcpServers": ...} for Cursor, Windsurf, Claude Desktop
```

Then ask your agent, for example: *"Use dapi to reverse engineer the API of the app I'm about to use. Start a
capture scoped to api.example.com."* The server ships a `reverse_engineer` prompt that walks through the whole
workflow. See [`examples/mcp.json`](examples/mcp.json) for a project-scoped config.

### MCP tools

| Tool | What it does | Network |
|---|---|---|
| `dapi_status` | Workspace overview: origins, endpoint and flow counts, capture state, suggested next steps | – |
| `capture_start` / `capture_stop` | Run a background mitmproxy recorder (regular, WireGuard, reverse, upstream modes) | proxy |
| `traffic_import` | Import a HAR (DevTools, Charles, Proxyman) or a mitmproxy dump | – |
| `scope_set` | Restrict which hosts are recorded and which may be contacted | – |
| `traffic_list` / `traffic_get` / `traffic_search` | Inspect redacted flows and see where secrets appeared | – |
| `endpoints_discover` / `endpoint_get` | Templated endpoint catalog with params, headers, statuses, auth requirement, evidence | – |
| `schema_infer` | JSON Schema for a request, or for a response per status | – |
| `auth_analyze` | Credential mechanisms, issuers (login/refresh), lifetimes, CSRF pairing, 401→refresh patterns | – |
| `dependencies_discover` | Data and auth edges between endpoints, plus a call order | – |
| `session_verify` | Calls read-only endpoints with vaulted credentials; optional unauthenticated probe and per-credential ablation | GET/HEAD |
| `session_refresh` | Replays the observed refresh flow (or the login flow when `allow_login=true`) | yes |
| `credentials_list` | Vault metadata (kind, where seen, JWT timing claims, expiry); never values | – |
| `client_generate` | Python (httpx) or TypeScript (fetch) client with typed models and login/refresh/retry | – |
| `docs_generate` | OpenAPI 3.1 or Markdown with `x-dapi-evidence-flows` annotations | – |

## Capturing traffic

| Source | How |
|---|---|
| CLI tools and scripts | `dapi capture`, then `HTTPS_PROXY=http://127.0.0.1:8080` and trust `~/.mitmproxy/mitmproxy-ca-cert.pem` (`curl --cacert`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`) |
| Browser | Start Chrome with `--proxy-server=http://127.0.0.1:8080` and install the CA from <http://mitm.it>, **or** save a HAR from DevTools and `dapi import file.har` (no proxy needed) |
| Mobile app | `dapi capture --listen-host 0.0.0.0` and set the phone's Wi-Fi proxy, or `dapi capture --mode wireguard` and scan the QR code. Install the CA from <http://mitm.it>. Apps with certificate pinning need extra work. |
| Python programs | `httpx.Client(transport=dapi.capture.httpx_recorder.RecordingTransport(Workspace()))` |
| Existing mitmproxy setups | `mitmdump -s $(python -c "import dapi.capture.addon as a; print(a.__file__)") --set dapi_home=.dapi`, or `dapi import flows.mitm` |

Set a scope (`dapi init --scope api.example.com --scope '*.example.com'`) so that only the target's API
traffic is recorded. Static assets (images, CSS, JS, fonts) are skipped by default.

## How it works

**Redaction at ingest.** Before a flow is stored, dapi vaults:

- auth headers (`Authorization`, `X-API-Key`, CSRF headers);
- every cookie and `Set-Cookie` value;
- body, query and form fields whose names mean credentials (`password`, `access_token`, `refresh_token`,
  `client_secret`, `api_key`, `code` and so on);
- identity fields (`username`, `email`) that sit next to a password;
- JWTs and `Bearer …` strings anywhere.

Any value already in the vault is also scrubbed wherever it shows up again, including URL-encoded, JSON-escaped and
base64 copies. Each secret is replaced by `{{secret:<ref>}}`, where the ref is an HMAC of the value.

**Credential lineage.** Refs are deterministic, so the access token in a login response
(`body:$.access_token`) and the `Authorization: Bearer` header of a later request share a ref. That link is
the evidence for *"issued by POST /auth/login, used by 14 requests to 5 endpoints"*. When a token rotates
(refresh, re-login), dapi follows the lineage: the newest secret issued at the same response location
replaces the old one. That is how verification and generated clients always use current credentials.

**Endpoint discovery.** dapi templates identifier-like path segments: integers, UUIDs, hex, dates, emails
and mixed tokens. It also turns varying literal segments into parameters, but only when the responses have the
same shape: `/users/alice` and `/users/bob` merge, while `/api/users` and `/api/orders` don't. Schemas are
merged across every sample; keys missing from some samples become optional.

**Auth requirements are proven, not guessed.** An endpoint is `auth: yes` only when a request without
credentials was rejected. `session_verify(probe_auth=true)` collects that evidence safely. It sends each
read-only request without credentials, then drops one credential at a time (ablation) to learn which one
actually matters. In the demo, that test finds the bearer token REQUIRED and the `sid` cookie NOT required.

**Grounded codegen.** Generated clients use the auth strategy that ablation proved. They replay the
observed login and refresh request bodies as templates, with credentials as parameters, and read new tokens
from the JSON paths where they were observed. They refresh proactively before expiry and reactively on 401.
Every method's docstring cites its evidence flows, statuses and auth evidence.

See [docs/security.md](docs/security.md) for the threat model and [docs/architecture.md](docs/architecture.md)
for module-level details and extension points.

## CLI reference

```text
dapi init [--scope HOST]...           create .dapi/ (git-ignored; holds flows + encrypted vault)
dapi capture [--port 8080] [--scope] [--mode wireguard|reverse:URL|upstream:URL] [--listen-host 0.0.0.0] [-- mitmdump args]
dapi import FILE                      HAR or mitmproxy dump
dapi status | flows [ID] | endpoints | endpoint ID | auth | deps
dapi verify [--probe-auth] [--allow-login] [--endpoint ID]...
dapi refresh [--allow-login]
dapi generate --lang python|typescript [-o DIR] [--class-name NAME]
dapi docs --format openapi|markdown [-o PATH]
dapi creds list | creds delete REF    vault metadata only
dapi session show | session set --origin URL --header 'Authorization' --cookie 'sid'   (values prompted, hidden)
dapi run -- python script.py          run a program with the session in <PREFIX>_TOKEN / _COOKIES / _HEADERS env vars
dapi mcp                              MCP server (stdio)
dapi mcp-config --client claude|codex|json
```

The workspace is the nearest `.dapi/` directory, `$DAPI_HOME`, or `--home`. The vault key comes from
`$DAPI_VAULT_KEY`, then the OS keyring (`pip install 'dapi[keyring]'`), then a `0600` key file inside the
workspace.

## Development

```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/pytest            # unit + end-to-end tests: real mitmproxy, demo API, MCP over stdio, tsc + node
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

Agents working on this repository: see [AGENTS.md](AGENTS.md).

## Status and roadmap

This is an MVP focused on REST/JSON over HTTP(S). Planned next:

- GraphQL operation-level cataloging
- WebSocket and SSE flows
- multipart bodies
- OAuth PKCE and redirect flow mapping
- request signing (HMAC) detection
- per-endpoint rate-limit observations
- more client languages

Contributions are welcome. See the extension points in [docs/architecture.md](docs/architecture.md).

## License

MIT
