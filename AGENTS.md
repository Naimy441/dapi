# Agent guide for the dapi repository

dapi is a Python 3.11+ package (`src/dapi`) that captures HTTP traffic with mitmproxy, redacts secrets
into an encrypted vault, analyzes endpoints and auth flows, and exposes everything over MCP.

## Setup and checks
```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/pytest -q                 # ~40s; includes real mitmproxy, MCP-over-stdio and tsc/node tests
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```
Tests use `examples/demo_api.py`, a stdlib HTTP server, and `tests/scenario.py`, which drives it like an app.

## Invariants to preserve
- **Never persist, log or return raw secrets.** All data reaching the model goes through `DapiService`
  methods decorated with `@safe`. New outputs must too. `tests/test_e2e.py::assert_no_secrets` and
  `test_nothing_secret_hits_disk` guard this; extend them when you add outputs.
- **Ground claims in evidence.** Analyses must cite flow ids. Don't add heuristics whose conclusions can't
  be traced back to flows.
- **Network actions stay conservative.** Verification sends only GET/HEAD to catalogued, in-scope,
  non-mutating endpoints. Login replay stays opt-in.
- Generated clients must not embed credentials. They must still compile (`tsc --strict`) and run against
  the demo API.

## Where things are
See `docs/architecture.md` for the module map and extension points, and `docs/security.md` for the
threat model.
