"""Converters from capture formats (mitmproxy flows, HAR) to :class:`RawExchange`."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from dapi.models import RawExchange


def flow_to_raw(flow: Any, source: str = "mitmproxy") -> RawExchange:
    """Convert a ``mitmproxy.http.HTTPFlow``."""
    req = flow.request
    resp = flow.response
    raw = RawExchange(
        method=req.method,
        url=req.pretty_url,
        req_headers=[(k, v) for k, v in req.headers.items(multi=True)],
        req_body=req.get_content(strict=False) or None,
        ts=req.timestamp_start or 0.0,
        source=source,
        http_version=req.http_version,
    )
    if resp is not None:
        raw.status = resp.status_code
        raw.resp_headers = [(k, v) for k, v in resp.headers.items(multi=True)]
        raw.resp_body = resp.get_content(strict=False) or None
        if resp.timestamp_end and req.timestamp_start:
            raw.duration_ms = (resp.timestamp_end - req.timestamp_start) * 1000
    if flow.error is not None:
        raw.error = str(flow.error.msg)
    return raw


def read_mitm_file(path: Path) -> Iterator[RawExchange]:
    from mitmproxy import http, io

    with open(path, "rb") as fh:
        for flow in io.FlowReader(fh).stream():
            if isinstance(flow, http.HTTPFlow):
                yield flow_to_raw(flow, source="mitm-file")


def _har_body(content: dict[str, Any] | None) -> bytes | None:
    if not content:
        return None
    text = content.get("text")
    if text is None:
        return None
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text)
        except ValueError:
            return None
    return text.encode("utf-8")


def _har_time(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def read_har(path: Path) -> Iterator[RawExchange]:
    """Read a HAR 1.2 file (browser DevTools "Save all as HAR", Charles, Proxyman, ...)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for entry in data.get("log", {}).get("entries", []):
        req, resp = entry.get("request", {}), entry.get("response", {})
        headers = [(h["name"], h["value"]) for h in req.get("headers", []) if not h["name"].startswith(":")]
        if req.get("cookies") and not any(k.lower() == "cookie" for k, _ in headers):
            headers.append(("Cookie", "; ".join(f"{c['name']}={c['value']}" for c in req["cookies"])))
        post = req.get("postData") or {}
        if post.get("mimeType") and not any(k.lower() == "content-type" for k, _ in headers):
            headers.append(("Content-Type", post["mimeType"]))
        status = resp.get("status") or None
        content = resp.get("content") or {}
        resp_headers = [(h["name"], h["value"]) for h in resp.get("headers", [])]
        if content.get("mimeType") and not any(k.lower() == "content-type" for k, _ in resp_headers):
            resp_headers.append(("Content-Type", content["mimeType"]))
        yield RawExchange(
            method=req.get("method", "GET"),
            url=req.get("url", ""),
            req_headers=headers,
            req_body=post.get("text", "").encode("utf-8") if post.get("text") else None,
            status=status if status and status > 0 else None,
            resp_headers=resp_headers,
            resp_body=_har_body(content),
            ts=_har_time(entry.get("startedDateTime")),
            duration_ms=entry.get("time"),
            source="har",
            error=None if status else (resp.get("_error") or "no response"),
        )


def import_file(ws: Any, path: Path) -> dict[str, Any]:
    path = Path(path)
    with open(path, "rb") as fh:
        first = fh.read(64).lstrip()[:1]
    if path.suffix.lower() == ".har" or first == b"{":
        reader, fmt = read_har(path), "har"
    else:
        reader, fmt = read_mitm_file(path), "mitmproxy"
    seen = recorded = 0
    for raw in reader:
        seen += 1
        if ws.ingest(raw) is not None:
            recorded += 1
    return {"format": fmt, "entries": seen, "recorded": recorded, "skipped": seen - recorded}
