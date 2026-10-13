from __future__ import annotations

import sys
import threading
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "examples"), str(Path(__file__).parent)]

from demo_api import serve  # noqa: E402
from scenario import run_demo_session  # noqa: E402

from dapi import Workspace  # noqa: E402
from dapi.capture.httpx_recorder import RecordingTransport  # noqa: E402

SECRETS = ["demo-password"]


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    monkeypatch.delenv("DAPI_HOME", raising=False)
    monkeypatch.delenv("DAPI_VAULT_KEY", raising=False)


def start_demo(ttl: int = 300):
    server = serve(0, ttl=ttl)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def demo():
    server, base = start_demo()
    yield base
    server.shutdown()


@pytest.fixture
def short_ttl_demo():
    server, base = start_demo(ttl=2)
    yield base
    server.shutdown()


@pytest.fixture
def ws(tmp_path) -> Workspace:
    return Workspace(tmp_path / ".dapi")


def record(ws: Workspace, base: str, expire_wait: float = 0.0) -> None:
    with httpx.Client(transport=RecordingTransport(ws)) as client:
        run_demo_session(client, base, expire_wait=expire_wait)


@pytest.fixture
def recorded(ws, demo):
    record(ws, demo)
    return ws, demo


def raw_storage_bytes(ws: Workspace) -> bytes:
    """Everything dapi persisted except the (encrypted) vault key."""
    data = b""
    for p in ws.home.iterdir():
        if p.is_file() and p.name != "vault.key":
            data += p.read_bytes()
    return data
