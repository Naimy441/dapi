# Security model

dapi handles live credentials for real accounts. Its job is to make them usable by programs while
keeping them away from language models, logs, and files that get shared or committed.

## What is protected, and where it lives

| Data | Storage | Visible to the model? |
|---|---|---|
| Secret values (tokens, cookies, passwords, API keys, usernames next to passwords) | `secrets` table, Fernet-encrypted (AES-128-CBC + HMAC-SHA256) | No: only `{{secret:s_…}}` refs |
| Secret metadata (kind, where seen, JWT `exp`/`iat`/`iss`/`aud`/`scope`, cookie attributes, length) | `secrets.meta` (plaintext) | Yes |
| Redacted flows (URLs, headers, bodies with placeholders) | `flows` table | Yes (truncated) |
| Vault key | `$DAPI_VAULT_KEY`, then the OS keyring, then `.dapi/vault.key` (mode 0600) | No |

The `.dapi/` directory is created with mode 0700 and contains a `.gitignore` of `*`.

## Redaction pipeline (ingest time)

1. **Structural rules.** dapi vaults the following:
   - `Authorization` and `Proxy-Authorization` (the scheme is kept: `Bearer {{secret:…}}`);
   - headers whose names indicate credentials (`X-API-Key`, `X-CSRF-Token`, `*token*`, `*session*`, …);
   - all `Cookie` values and `Set-Cookie` values (attributes are kept for expiry analysis);
   - JSON, form and query fields whose names indicate credentials;
   - identity fields (`username`, `email`, `login`, `phone`) when they sit beside a password.
2. **Patterns.** JWTs and `Bearer …` strings are vaulted wherever they appear: free text, HTML and paths.
3. **Known values.** After structural redaction, every string is scrubbed for any value already in the
   vault, including URL-encoded, JSON-escaped and base64 variants. This catches tokens reflected in
   responses, redirects or logs.

Custom field names can be added with `extra_secret_keys` in `.dapi/config.json`.

Refs are `HMAC-SHA256(vault key, value)` truncated to 40 bits. They are deterministic within a workspace,
so dapi can link where a credential was issued to where it was used. Without the key, a ref reveals nothing
about the value.

## Output guards

- Every MCP tool and CLI JSON result goes through `Vault.scrub_obj` before it is returned. This is a second,
  independent pass on top of ingest redaction.
- mitmproxy runs with `flow_detail=0`, so its console never prints raw flows. dapi logs only redacted summaries.
- Generated clients never embed credentials. They take them as arguments, from environment variables
  (`<PREFIX>_TOKEN`, …) or from `from_dapi()`, which decrypts the vault inside the user's own process.

## Network actions and their safeguards

| Action | Safeguards |
|---|---|
| `session_verify` | Only `GET`/`HEAD` to endpoints already in the catalog, never paths that look state-changing (`logout`, `delete`, `revoke`, `reset`, …). Host must be in scope. At most 10 endpoints per call. Every request is recorded as evidence (`source=dapi-verify` / `dapi-probe`). |
| `session_refresh` | Replays the observed refresh request. Login replay needs an explicit `allow_login=true`. |
| `capture_start` | Listens on `127.0.0.1` unless told otherwise. Records only in-scope hosts when a scope is set. |

## Known limitations

- Secrets inside binary, multipart or very large (>512 KB) bodies are covered only by pattern and
  known-value scrubbing.
- Short secrets (under 6 characters, e.g. PINs) are not scrubbed by value outside their structural location,
  to avoid false positives.
- Non-standard credential field names may be missed. Add them to `extra_secret_keys`, then re-import.
- `secrets.meta` keeps JWT timing and issuer claims in plaintext. Other claims (`sub`, `email`, …) are dropped.
- The vault protects data at rest and keeps it out of model context. It does not defend against malware
  running as the same OS user.

## Responsible use

Only capture traffic from applications and accounts you own or are explicitly authorized to test.
Respect the target's terms of service and rate limits.
