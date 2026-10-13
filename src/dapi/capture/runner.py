"""Run mitmproxy with the dapi recorder, in the foreground or as a managed background process."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from dapi.workspace import Workspace

ADDON_PATH = Path(__file__).with_name("addon.py")


def mitmdump_args(
    home: Path,
    port: int,
    scope: list[str] | None,
    mode: str | None,
    listen_host: str,
    extra: list[str] | None = None,
) -> list[str]:
    args = [
        "-s",
        str(ADDON_PATH),
        "--listen-host",
        listen_host,
        "--listen-port",
        str(port),
        "--set",
        "flow_detail=0",  # never print unredacted flows to the console
        "--set",
        f"dapi_home={home}",
    ]
    if scope:
        args += ["--set", "dapi_scope=" + ",".join(scope)]
    if mode:
        args += ["--mode", mode]
    return args + list(extra or [])


def run_foreground(
    ws: Workspace,
    port: int = 8080,
    scope: list[str] | None = None,
    mode: str | None = None,
    listen_host: str = "127.0.0.1",
    extra: list[str] | None = None,
) -> int:
    from mitmproxy.tools.main import mitmdump

    args = mitmdump_args(ws.home, port, scope, mode, listen_host, extra)
    return mitmdump(args) or 0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _port_open(host: str, port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def status(ws: Workspace) -> dict[str, Any]:
    info = ws.store.kv_get("capture") or {}
    pid = info.get("pid")
    running = bool(pid) and _pid_alive(pid)
    return {"running": running, **info} if info else {"running": False}


def start_background(
    ws: Workspace,
    port: int = 8080,
    scope: list[str] | None = None,
    mode: str | None = None,
    listen_host: str = "127.0.0.1",
    wait: float = 15.0,
    ssl_insecure: bool = False,
) -> dict[str, Any]:
    current = status(ws)
    if current.get("running"):
        return {**current, "note": "capture already running"}
    if _port_open(listen_host, port):
        raise RuntimeError(f"port {port} on {listen_host} is already in use")
    log_path = ws.home / "capture.log"
    cmd = [
        sys.executable,
        "-m",
        "dapi.cli",
        "--home",
        str(ws.home),
        "capture",
        "--port",
        str(port),
        "--listen-host",
        listen_host,
    ]
    for s in scope or []:
        cmd += ["--scope", s]
    if mode:
        cmd += ["--mode", mode]
    if ssl_insecure:
        cmd.append("--ssl-insecure")
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(
            cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True
        )
    deadline = time.time() + wait
    while time.time() < deadline:
        if proc.poll() is not None:
            tail = log_path.read_text(errors="replace")[-1500:]
            raise RuntimeError(f"capture process exited with code {proc.returncode}:\n{tail}")
        if _port_open(listen_host, port):
            break
        time.sleep(0.2)
    else:
        proc.terminate()
        raise RuntimeError("timed out waiting for mitmproxy to start; see " + str(log_path))
    info = {
        "pid": proc.pid,
        "port": port,
        "listen_host": listen_host,
        "mode": mode or "regular",
        "scope": scope or ws.config.scope,
        "started": time.time(),
        "log": str(log_path),
        "proxy_url": f"http://{listen_host}:{port}",
    }
    ws.store.kv_set("capture", info)
    return {"running": True, **info, **setup_hints(listen_host, port, mode)}


def stop_background(ws: Workspace) -> dict[str, Any]:
    info = status(ws)
    if not info.get("running"):
        ws.store.kv_set("capture", {})
        return {"stopped": False, "note": "capture was not running"}
    os.kill(info["pid"], signal.SIGTERM)
    for _ in range(50):
        if not _pid_alive(info["pid"]):
            break
        time.sleep(0.1)
    else:
        os.kill(info["pid"], signal.SIGKILL)
    ws.store.kv_set("capture", {})
    return {"stopped": True, "pid": info["pid"], "flows_total": ws.store.flow_count()}


def setup_hints(listen_host: str, port: int, mode: str | None) -> dict[str, Any]:
    ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    proxy = f"http://{listen_host}:{port}"
    hints = {
        "ca_certificate": str(ca),
        "how_to_route_traffic": [
            f"CLI tools: export HTTPS_PROXY={proxy} HTTP_PROXY={proxy} and trust {ca} "
            f"(e.g. curl --cacert {ca}, NODE_EXTRA_CA_CERTS={ca}, REQUESTS_CA_BUNDLE={ca})",
            f"Browser: start Chrome with --proxy-server={proxy} --ignore-certificate-errors-spki-list=<spki> "
            "or install the CA from http://mitm.it while proxied",
            "Mobile: set the device's Wi-Fi proxy to this machine (listen on 0.0.0.0) and install the CA from "
            "http://mitm.it, or use --mode wireguard and scan the QR code mitmproxy prints",
        ],
    }
    if mode and mode.startswith("wireguard"):
        hints["how_to_route_traffic"].insert(
            0, "WireGuard mode: import the client config printed in the capture log"
        )
    return hints
