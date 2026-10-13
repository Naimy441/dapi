"""Core data types shared across capture, analysis and code generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

Pairs = list[tuple[str, str]]


@dataclass
class RawExchange:
    """An unredacted HTTP request/response pair, straight from a capture source.

    RawExchange objects never leave process memory: they are redacted into an
    :class:`Exchange` before being stored, logged or shown to a model.
    """

    method: str
    url: str
    req_headers: Pairs
    req_body: bytes | None = None
    status: int | None = None
    resp_headers: Pairs = field(default_factory=list)
    resp_body: bytes | None = None
    ts: float = 0.0
    duration_ms: float | None = None
    source: str = "unknown"
    error: str | None = None
    http_version: str | None = None


@dataclass
class Exchange:
    """A redacted, persisted HTTP exchange. Secrets appear as ``{{secret:s_...}}`` placeholders."""

    id: int | None
    ts: float
    method: str
    scheme: str
    host: str
    port: int
    path: str
    query: Pairs
    req_headers: Pairs
    req_body: str | None
    req_content_type: str
    status: int | None
    resp_headers: Pairs
    resp_body: str | None
    resp_content_type: str
    duration_ms: float | None = None
    source: str = "unknown"
    error: str | None = None
    req_size: int = 0
    resp_size: int = 0

    @property
    def origin(self) -> str:
        return make_origin(self.scheme, self.host, self.port)

    def req_header(self, name: str) -> str | None:
        return header_get(self.req_headers, name)

    def resp_header(self, name: str) -> str | None:
        return header_get(self.resp_headers, name)

    def summary(self) -> dict:
        return {
            "id": self.id,
            "ts": round(self.ts, 3),
            "method": self.method,
            "url": self.origin
            + self.path
            + (("?" + "&".join(f"{k}={v}" for k, v in self.query)) if self.query else ""),
            "status": self.status,
            "resp_content_type": self.resp_content_type or None,
            "resp_size": self.resp_size,
            "source": self.source,
            **({"error": self.error} if self.error else {}),
        }


DEFAULT_PORTS = {"http": 80, "https": 443}


def make_origin(scheme: str, host: str, port: int) -> str:
    if DEFAULT_PORTS.get(scheme) == port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def split_url(url: str) -> tuple[str, str, int, str, str]:
    """Return (scheme, host, port, path, query_string)."""
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    port = parts.port or DEFAULT_PORTS.get(scheme, 80)
    return scheme, host, port, parts.path or "/", parts.query


def header_get(headers: Pairs, name: str) -> str | None:
    lname = name.lower()
    for k, v in headers:
        if k.lower() == lname:
            return v
    return None


def header_all(headers: Pairs, name: str) -> list[str]:
    lname = name.lower()
    return [v for k, v in headers if k.lower() == lname]


def media_type(content_type: str | None) -> str:
    return (content_type or "").split(";")[0].strip().lower()


def is_json_type(content_type: str | None) -> bool:
    mt = media_type(content_type)
    return mt == "application/json" or mt.endswith("+json") or mt == "text/json"


def is_form_type(content_type: str | None) -> bool:
    return media_type(content_type) == "application/x-www-form-urlencoded"


def is_text_type(content_type: str | None) -> bool:
    mt = media_type(content_type)
    return (
        mt.startswith("text/")
        or is_json_type(mt)
        or is_form_type(mt)
        or mt in {"application/xml", "application/javascript", "application/graphql", "application/x-ndjson"}
        or mt.endswith("+xml")
    )
