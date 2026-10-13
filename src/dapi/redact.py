"""Secret redaction.

Every captured exchange passes through :class:`Redactor` before it is stored.
Credentials are moved into the encrypted :class:`~dapi.vault.Vault` and
replaced by ``{{secret:s_...}}`` placeholders. Because references are
deterministic, the analysis layer can still follow a token from the response
that issued it to every request that used it, without ever seeing the value.

Detection is layered:

1. Structural: auth headers, cookies, Set-Cookie values, and body / query /
   form fields whose *names* indicate a credential (``password``,
   ``access_token``, ``api_key``, ``csrf`` ...). Identity fields (``username``,
   ``email``) are vaulted when they appear next to a password.
2. Pattern: JWTs and ``Bearer ...`` strings anywhere.
3. Known values: any value already in the vault is scrubbed wherever it
   reappears (reflected tokens, URL-encoded copies, base64 copies).
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, quote

from dapi.models import (
    Exchange,
    Pairs,
    RawExchange,
    header_get,
    is_form_type,
    is_json_type,
    is_text_type,
    make_origin,
    media_type,
    split_url,
)
from dapi.vault import PLACEHOLDER_RE, Vault, placeholder, refs_in

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
BEARER_RE = re.compile(r"(?i)\b(bearer)\s+([A-Za-z0-9\-._~+/]{8,}=*)")

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-csrftoken",
    "x-session-token",
    "x-session-id",
    "x-amz-security-token",
    "x-goog-api-key",
    "x-refresh-token",
    "x-id-token",
}
SENSITIVE_HEADER_RE = re.compile(
    r"(?i)(token|secret|api[-_]?key|apikey|auth|session|csrf|xsrf|signature|password|credential)"
)
NON_SECRET_HEADERS = {
    "www-authenticate",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-allow-credentials",
    "access-control-request-headers",
    "authority",
    ":authority",
    "x-auth-required",
    "proxy-authenticate",
}
NON_SECRET_KEY_SUFFIXES = (
    "type",
    "expiresin",
    "expiresat",
    "expiry",
    "expires",
    "expiration",
    "ttl",
    "url",
    "uri",
    "endpoint",
    "required",
    "enabled",
    "policy",
    "hint",
    "length",
    "count",
    "method",
    "methods",
    "provider",
    "scheme",
    "status",
    "valid",
    "strength",
    "minlength",
    "maxlength",
    "header",
    "name",
    "lifetime",
)
IDENTITY_KEYS = {
    "username",
    "user",
    "email",
    "emailaddress",
    "login",
    "phone",
    "phonenumber",
    "account",
    "userid",
}
PASSWORD_KEYS = {"password", "passwd", "pass", "pwd", "passcode", "passphrase"}
EXACT_SECRET_KEYS = {
    "otp",
    "totp",
    "mfacode",
    "pin",
    "cvv",
    "cvc",
    "ssn",
    "cardnumber",
    "privatekey",
    "signature",
    "sig",
    "credential",
    "credentials",
    "assertion",
    "samlresponse",
    "code",
    "nonce",
    "codeverifier",
}
KEEP_JWT_CLAIMS = ("exp", "iat", "nbf", "iss", "aud", "scope", "scp", "typ", "token_use", "azp")


def norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def classify_key(key: str) -> str | None:
    """Return a secret kind for a field name, or None if the name does not indicate a secret."""
    k = norm_key(key)
    if not k or k.endswith(NON_SECRET_KEY_SUFFIXES):
        return None
    if "refresh" in k and "token" in k:
        return "refresh_token"
    if k in PASSWORD_KEYS or "password" in k:
        return "password"
    if "secret" in k:
        return "secret"
    if "accesstoken" in k:
        return "access_token"
    if "idtoken" in k:
        return "id_token"
    if "csrf" in k or "xsrf" in k:
        return "csrf"
    if "token" in k:
        return "token"
    if "apikey" in k or k in {"key", "appkey", "subscriptionkey"}:
        return "api_key"
    if k in {"authorization", "auth"}:
        return "auth"
    if "session" in k or k == "sid":
        return "session"
    if k in EXACT_SECRET_KEYS:
        return "secret"
    return None


def jwt_claims(token: str) -> dict[str, Any] | None:
    """Decode the (unverified) payload of a JWT and keep only non-identifying, timing-related claims."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None
    return {k: claims[k] for k in KEEP_JWT_CLAIMS if k in claims}


def parse_cookie_header(value: str) -> list[tuple[str, str]]:
    out = []
    for part in value.split(";"):
        if not part.strip():
            continue
        name, _, val = part.strip().partition("=")
        out.append((name.strip(), val.strip()))
    return out


def parse_set_cookie(value: str) -> tuple[str, str, dict[str, Any]]:
    first, *attrs = value.split(";")
    name, _, val = first.strip().partition("=")
    meta: dict[str, Any] = {}
    for attr in attrs:
        a_name, _, a_val = attr.strip().partition("=")
        a = a_name.strip().lower()
        if a == "max-age":
            try:
                meta["max_age"] = int(a_val)
            except ValueError:
                pass
        elif a in {"expires", "domain", "path", "samesite"}:
            meta[a] = a_val.strip()
        elif a in {"httponly", "secure"}:
            meta[a] = True
    return name.strip(), val.strip(), meta


class Redactor:
    def __init__(
        self, vault: Vault, max_body_bytes: int = 512 * 1024, extra_secret_keys: list[str] | None = None
    ):
        self.vault = vault
        self.max_body_bytes = max_body_bytes
        self.extra_secret_keys = {norm_key(k) for k in (extra_secret_keys or [])}

    # -- helpers ---------------------------------------------------------------------------
    def _kind_for_key(self, key: str) -> str | None:
        if norm_key(key) in self.extra_secret_keys:
            return "secret"
        return classify_key(key)

    def _vault(self, value: str, kind: str, **meta: Any) -> str:
        if kind in {"jwt", "bearer", "access_token", "id_token", "token", "refresh_token", "auth"}:
            claims = jwt_claims(value)
            if claims:
                meta["jwt"] = claims
        return placeholder(self.vault.put(value, kind, {k: v for k, v in meta.items() if v is not None}))

    def scrub_string(self, text: str, **meta: Any) -> str:
        """Pattern + known-value scrubbing for free-form strings."""
        if not text:
            return text
        if PLACEHOLDER_RE.fullmatch(text):
            return text
        text = JWT_RE.sub(lambda m: self._vault(m.group(0), "jwt", **meta), text)
        text = BEARER_RE.sub(
            lambda m: (
                m.group(1)
                + " "
                + (
                    m.group(2)
                    if PLACEHOLDER_RE.search(m.group(2))
                    else self._vault(m.group(2), "bearer", **meta)
                )
            ),
            text,
        )
        return self.vault.scrub(text)

    # -- headers ---------------------------------------------------------------------------
    def redact_headers(self, headers: Pairs, side: str, origin: str, ts: float) -> Pairs:
        out: Pairs = []
        for name, value in headers:
            lname = name.lower()
            if lname == "cookie":
                parts = [
                    f"{c_name}={self._vault(c_val, 'cookie', name=c_name, origin=origin) if c_val else ''}"
                    for c_name, c_val in parse_cookie_header(value)
                ]
                out.append((name, "; ".join(parts)))
            elif lname == "set-cookie":
                c_name, c_val, attrs = parse_set_cookie(value)
                if c_val and c_val.lower() not in {"deleted", '""', "null"}:
                    expires_at = ts + attrs["max_age"] if "max_age" in attrs else None
                    ref_text = self._vault(
                        c_val,
                        "cookie",
                        name=c_name,
                        origin=origin,
                        issued_at=ts,
                        cookie_attrs=attrs,
                        expires_at=expires_at,
                    )
                    rest = value.split(";", 1)[1] if ";" in value else ""
                    out.append((name, f"{c_name}={ref_text}" + (";" + rest if rest else "")))
                else:
                    out.append((name, value))
            elif lname in {"authorization", "proxy-authorization"}:
                scheme, _, cred = value.partition(" ")
                if cred and scheme.lower() in {"bearer", "basic", "token", "jwt", "dpop", "mac", "apikey"}:
                    kind = {"bearer": "bearer", "basic": "basic"}.get(scheme.lower(), "auth")
                    out.append(
                        (name, f"{scheme} {self._vault(cred.strip(), kind, header=name, origin=origin)}")
                    )
                else:
                    out.append((name, self._vault(value, "auth", header=name, origin=origin)))
            elif (
                lname not in NON_SECRET_HEADERS
                and (lname in SENSITIVE_HEADERS or SENSITIVE_HEADER_RE.search(lname))
                and len(value) >= 4
                and not PLACEHOLDER_RE.fullmatch(value)
            ):
                kind = (
                    "csrf"
                    if ("csrf" in lname or "xsrf" in lname)
                    else ("api_key" if "key" in lname else "token")
                )
                out.append((name, self._vault(value, kind, header=name, origin=origin)))
            else:
                out.append((name, self.scrub_string(value, origin=origin)))
        return out

    # -- bodies ----------------------------------------------------------------------------
    def _redact_json(self, obj: Any, origin: str, ts: float, path: str = "$") -> Any:
        if isinstance(obj, dict):
            has_password = any(self._kind_for_key(k) == "password" for k in obj if isinstance(obj[k], str))
            expires_in = None
            for key in ("expires_in", "expiresIn", "expires"):
                if isinstance(obj.get(key), int | float) and not isinstance(obj.get(key), bool):
                    expires_in = obj[key]
                    break
            out = {}
            for key, value in obj.items():
                child_path = f"{path}.{key}"
                kind = self._kind_for_key(key)
                if has_password and norm_key(key) in IDENTITY_KEYS and isinstance(value, str) and value:
                    kind = "username"
                if kind and isinstance(value, str) and value and not PLACEHOLDER_RE.fullmatch(value):
                    if kind in {"token", "secret", "session", "auth"} and len(value) < 4:
                        out[key] = value
                        continue
                    meta: dict[str, Any] = {"field": child_path, "origin": origin, "issued_at": ts}
                    if expires_in is not None and kind in {
                        "access_token",
                        "token",
                        "id_token",
                        "session",
                        "auth",
                    }:
                        meta["expires_in"] = expires_in
                        meta["expires_at"] = ts + float(expires_in)
                    out[key] = self._vault(value, kind, **meta)
                elif (
                    kind in {"password", "secret"}
                    and isinstance(value, int | float)
                    and not isinstance(value, bool)
                ):
                    out[key] = self._vault(str(value), kind, field=child_path, origin=origin)
                else:
                    out[key] = self._redact_json(value, origin, ts, child_path)
            return out
        if isinstance(obj, list):
            return [self._redact_json(v, origin, ts, path + "[]") for v in obj]
        if isinstance(obj, str):
            return self.scrub_string(obj, origin=origin, field=path)
        return obj

    def _redact_form(self, text: str, origin: str, ts: float) -> str:
        pairs = parse_qsl(text, keep_blank_values=True)
        has_password = any(self._kind_for_key(k) == "password" for k, _ in pairs)
        parts = []
        for key, value in pairs:
            kind = self._kind_for_key(key)
            if has_password and norm_key(key) in IDENTITY_KEYS and value:
                kind = "username"
            if kind and value and not (kind in {"token", "secret", "session"} and len(value) < 4):
                red = self._vault(value, kind, field=f"form:{key}", origin=origin, issued_at=ts)
            else:
                red = self.scrub_string(value, origin=origin)
            enc = red if PLACEHOLDER_RE.fullmatch(red) else quote(red, safe="{}:")
            parts.append(f"{quote(key, safe='')}={enc}")
        return "&".join(parts)

    def redact_body(self, body: bytes | None, content_type: str, origin: str, ts: float) -> str | None:
        if body is None or len(body) == 0:
            return None
        truncated = len(body) > self.max_body_bytes
        chunk = body[: self.max_body_bytes]
        if not is_text_type(content_type):
            if b"\x00" in chunk[:2048] or media_type(content_type).startswith(
                ("image/", "audio/", "video/", "font/")
            ):
                return f"<binary body: {len(body)} bytes, {media_type(content_type) or 'unknown type'}>"
        text = chunk.decode("utf-8", errors="replace")
        if is_json_type(content_type) or (not content_type and text.lstrip()[:1] in "{["):
            if not truncated:
                try:
                    data = json.loads(text)
                except ValueError:
                    data = None
                else:
                    redacted = self._redact_json(data, origin, ts)
                    return self.vault.scrub(json.dumps(redacted, ensure_ascii=False))
        if is_form_type(content_type) and not truncated:
            return self.vault.scrub(self._redact_form(text, origin, ts))
        text = self.scrub_string(text, origin=origin)
        if truncated:
            text += f"\n<truncated: {len(body)} bytes total>"
        return text

    def _redact_query(self, query: str, origin: str, ts: float) -> Pairs:
        out: Pairs = []
        for key, value in parse_qsl(query, keep_blank_values=True):
            kind = self._kind_for_key(key)
            if kind and value and len(value) >= 4:
                out.append((key, self._vault(value, kind, field=f"query:{key}", origin=origin, issued_at=ts)))
            else:
                out.append((key, self.scrub_string(value, origin=origin)))
        return out

    # -- exchange --------------------------------------------------------------------------
    def redact(self, raw: RawExchange) -> tuple[Exchange, list[tuple[str, str, str]]]:
        scheme, host, port, path, query = split_url(raw.url)
        origin = make_origin(scheme, host, port)
        req_ct = header_get(raw.req_headers, "content-type") or ""
        resp_ct = header_get(raw.resp_headers, "content-type") or ""
        ex = Exchange(
            id=None,
            ts=raw.ts,
            method=raw.method.upper(),
            scheme=scheme,
            host=host,
            port=port,
            path=self.scrub_string(path, origin=origin),
            query=self._redact_query(query, origin, raw.ts),
            req_headers=self.redact_headers(raw.req_headers, "request", origin, raw.ts),
            req_body=self.redact_body(raw.req_body, req_ct, origin, raw.ts),
            req_content_type=req_ct,
            status=raw.status,
            resp_headers=self.redact_headers(raw.resp_headers, "response", origin, raw.ts),
            resp_body=self.redact_body(raw.resp_body, resp_ct, origin, raw.ts),
            resp_content_type=resp_ct,
            duration_ms=raw.duration_ms,
            source=raw.source,
            error=self.scrub_string(raw.error) if raw.error else None,
            req_size=len(raw.req_body or b""),
            resp_size=len(raw.resp_body or b""),
        )
        return ex, extract_sightings(ex)


def _walk_json_refs(obj: Any, path: str, emit: Callable[[str, str], None]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk_json_refs(v, f"{path}.{k}", emit)
    elif isinstance(obj, list):
        for v in obj:
            _walk_json_refs(v, path + "[]", emit)
    elif isinstance(obj, str):
        for ref in refs_in(obj):
            emit(ref, f"body:{path}")


def body_ref_locations(body: str | None, content_type: str) -> list[tuple[str, str]]:
    """Return ``(ref, location)`` for each placeholder in a redacted body."""
    if not body:
        return []
    found: list[tuple[str, str]] = []
    emit = lambda ref, loc: found.append((ref, loc))  # noqa: E731
    if is_json_type(content_type) or body.lstrip()[:1] in "{[":
        try:
            _walk_json_refs(json.loads(body), "$", emit)
            return found
        except ValueError:
            pass
    if is_form_type(content_type):
        for part in body.split("&"):
            key, _, value = part.partition("=")
            for ref in refs_in(value):
                found.append((ref, f"form:{key}"))
        return found
    return [(ref, "body") for ref in refs_in(body)]


def extract_sightings(ex: Exchange) -> list[tuple[str, str, str]]:
    """Derive ``(ref, side, location)`` sightings from placeholders in a redacted exchange."""
    out: list[tuple[str, str, str]] = []
    for ref in refs_in(ex.path):
        out.append((ref, "request", "path"))
    for key, value in ex.query:
        for ref in refs_in(value):
            out.append((ref, "request", f"query:{key}"))
    for side, headers in (("request", ex.req_headers), ("response", ex.resp_headers)):
        for name, value in headers:
            lname = name.lower()
            if lname == "cookie":
                for c_name, c_val in parse_cookie_header(value):
                    for ref in refs_in(c_val):
                        out.append((ref, side, f"cookie:{c_name}"))
            elif lname == "set-cookie":
                c_name, c_val, _ = parse_set_cookie(value)
                for ref in refs_in(c_val):
                    out.append((ref, side, f"set-cookie:{c_name}"))
            else:
                for ref in refs_in(value):
                    out.append((ref, side, f"header:{name}"))
    for ref, loc in body_ref_locations(ex.req_body, ex.req_content_type):
        out.append((ref, "request", loc))
    for ref, loc in body_ref_locations(ex.resp_body, ex.resp_content_type):
        out.append((ref, "response", loc))
    return list(dict.fromkeys(out))
