"""Record traffic from Python programs that use httpx (no proxy or CA certificate needed).

import httpx
from dapi import Workspace
from dapi.capture.httpx_recorder import RecordingTransport

ws = Workspace()
client = httpx.Client(transport=RecordingTransport(ws))
"""

from __future__ import annotations

import time

import httpx

from dapi.models import RawExchange
from dapi.workspace import Workspace


class RecordingTransport(httpx.BaseTransport):
    def __init__(self, workspace: Workspace, inner: httpx.BaseTransport | None = None, source: str = "httpx"):
        self.ws = workspace
        self.inner = inner or httpx.HTTPTransport()
        self.source = source

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        started = time.time()
        body = request.read()
        response = self.inner.handle_request(request)
        content = response.read()
        self.ws.ingest(
            RawExchange(
                method=request.method,
                url=str(request.url),
                req_headers=list(request.headers.multi_items()),
                req_body=body or None,
                status=response.status_code,
                resp_headers=list(response.headers.multi_items()),
                resp_body=content or None,
                ts=started,
                duration_ms=(time.time() - started) * 1000,
                source=self.source,
            )
        )
        headers = [
            (k, v)
            for k, v in response.headers.multi_items()
            if k.lower() not in {"content-encoding", "content-length"}
        ]
        return httpx.Response(
            response.status_code,
            headers=headers,
            content=content,
            request=request,
            extensions=response.extensions,
        )

    def close(self) -> None:
        self.inner.close()
