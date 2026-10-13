"""A tiny, dependency-free demo API used by dapi's tests and quickstart.

Auth model (deliberately realistic):
  * POST /api/v1/auth/login     {username, password} -> JWT access token + rotating refresh token,
                                also sets an HttpOnly ``sid`` cookie (unused by the API, like many apps)
  * POST /api/v1/auth/refresh   {refresh_token}      -> new access + refresh tokens
  * POST /api/v1/auth/logout
  * Bearer token required for everything under /api/v1 except /auth/* and /public/*

Run:  python examples/demo_api.py --port 8765 --ttl 300
Login with demo / demo-password.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

SIGNING_KEY = b"demo-signing-key"
USERS = {"demo": {"password": "demo-password", "id": 7, "name": "Demo User", "email": "demo@example.com"}}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(sub: int, ttl: int) -> str:
    now = int(time.time())
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": str(sub), "iat": now, "exp": now + ttl, "iss": "demo-api"}).encode())
    sig = _b64(hmac.new(SIGNING_KEY, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def check_jwt(token: str) -> int | None:
    try:
        header, payload, sig = token.split(".")
        expected = _b64(hmac.new(SIGNING_KEY, f"{header}.{payload}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return int(claims["sub"]) if claims["exp"] > time.time() else None
    except Exception:
        return None


class State:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self.lock = threading.Lock()
        self.refresh_tokens: dict[str, int] = {}
        self.projects = {
            101: {
                "id": 101,
                "name": "Apollo",
                "owner_id": 7,
                "created_at": "2026-01-05T10:00:00Z",
                "archived": False,
            },
            102: {
                "id": 102,
                "name": "Gemini",
                "owner_id": 7,
                "created_at": "2026-02-11T09:30:00Z",
                "archived": False,
            },
            103: {
                "id": 103,
                "name": "Mercury",
                "owner_id": 7,
                "created_at": "2026-03-20T16:45:00Z",
                "archived": True,
            },
        }
        self.tasks = {
            101: [{"id": 1001, "project_id": 101, "title": "Design", "status": "open", "assignee": None}],
            102: [
                {
                    "id": 1002,
                    "project_id": 102,
                    "title": "Build",
                    "status": "done",
                    "assignee": {"id": 7, "name": "Demo User"},
                }
            ],
            103: [],
        }
        self.next_task = 2000

    def issue(self, user_id: int) -> dict:
        refresh = "rt_" + secrets.token_urlsafe(24)
        with self.lock:
            self.refresh_tokens[refresh] = user_id
        return {
            "access_token": make_jwt(user_id, self.ttl),
            "token_type": "Bearer",
            "expires_in": self.ttl,
            "refresh_token": refresh,
        }


def make_handler(state: State):
    class Handler(BaseHTTPRequestHandler):
        server_version = "DemoAPI/1.0"

        def log_message(self, fmt, *args):  # keep test output quiet
            pass

        def _send(self, status: int, body=None, headers: dict | None = None):
            data = json.dumps(body).encode() if body is not None else b""
            self.send_response(status)
            if body is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            if not raw:
                return {}
            if "application/x-www-form-urlencoded" in (self.headers.get("Content-Type") or ""):
                return {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            return json.loads(raw)

        def _user(self) -> int | None:
            auth = self.headers.get("Authorization") or ""
            return check_jwt(auth[7:]) if auth.startswith("Bearer ") else None

        def _graphql(self, body: dict):
            """Minimal GraphQL endpoint: dispatches on operationName (the document is not parsed)."""
            uid = self._user()
            if uid is None:
                return self._send(
                    200,
                    {
                        "data": None,
                        "errors": [{"message": "Unauthenticated", "extensions": {"code": "UNAUTHENTICATED"}}],
                    },
                )
            op, variables = body.get("operationName"), body.get("variables") or {}
            if op == "Viewer":
                u = next(v for v in USERS.values() if v["id"] == uid)
                return self._send(
                    200,
                    {
                        "data": {
                            "viewer": {"id": u["id"], "name": u["name"], "projectCount": len(state.projects)}
                        }
                    },
                )
            if op == "Project":
                p = state.projects.get(int(variables.get("id", 0)))
                if p is None:
                    return self._send(200, {"data": {"project": None}, "errors": [{"message": "Not found"}]})
                return self._send(200, {"data": {"project": {**p, "tasks": state.tasks[p["id"]]}}})
            if op == "CreateTask":
                pid = int(variables.get("projectId", 0))
                if pid not in state.projects:
                    return self._send(200, {"data": None, "errors": [{"message": "Project not found"}]})
                with state.lock:
                    state.next_task += 1
                    task = {
                        "id": state.next_task,
                        "project_id": pid,
                        "title": variables.get("title", ""),
                        "status": "open",
                        "assignee": None,
                    }
                    state.tasks[pid].append(task)
                return self._send(200, {"data": {"createTask": task}})
            return self._send(200, {"data": None, "errors": [{"message": f"Unknown operation {op}"}]})

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            url = urlsplit(self.path)
            parts = [p for p in url.path.split("/") if p]
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            if url.path == "/api/v1/public/health":
                return self._send(200, {"status": "ok", "version": "1.0.0"})
            uid = self._user()
            if uid is None:
                return self._send(401, {"error": "unauthorized"}, {"WWW-Authenticate": 'Bearer realm="demo"'})
            if url.path == "/api/v1/me":
                u = next(v for v in USERS.values() if v["id"] == uid)
                return self._send(200, {"id": u["id"], "name": u["name"], "email": u["email"]})
            if url.path == "/api/v1/projects":
                items = list(state.projects.values())
                if query.get("archived") in ("true", "false"):
                    items = [p for p in items if p["archived"] == (query["archived"] == "true")]
                return self._send(200, {"items": items, "total": len(items)})
            if len(parts) >= 4 and parts[:3] == ["api", "v1", "projects"] and parts[3].isdigit():
                pid = int(parts[3])
                if pid not in state.projects:
                    return self._send(404, {"error": "not found"})
                if len(parts) == 4:
                    return self._send(200, state.projects[pid])
                if len(parts) == 5 and parts[4] == "tasks":
                    tasks = state.tasks[pid]
                    if "status" in query:
                        tasks = [t for t in tasks if t["status"] == query["status"]]
                    return self._send(200, tasks)
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            url = urlsplit(self.path)
            parts = [p for p in url.path.split("/") if p]
            body = self._body()
            if url.path == "/api/v1/auth/login":
                user = USERS.get(body.get("username", ""))
                if not user or user["password"] != body.get("password"):
                    return self._send(401, {"error": "invalid credentials"})
                sid = secrets.token_hex(16)
                return self._send(
                    200,
                    state.issue(user["id"]),
                    {"Set-Cookie": f"sid={sid}; Path=/; Max-Age=86400; HttpOnly"},
                )
            if url.path == "/api/v1/auth/refresh":
                with state.lock:
                    uid = state.refresh_tokens.pop(body.get("refresh_token", ""), None)
                if uid is None:
                    return self._send(401, {"error": "invalid refresh token"})
                return self._send(200, state.issue(uid))
            if url.path == "/api/v1/auth/logout":
                return self._send(204)
            if url.path == "/api/graphql":
                return self._graphql(body)
            uid = self._user()
            if uid is None:
                return self._send(401, {"error": "unauthorized"}, {"WWW-Authenticate": 'Bearer realm="demo"'})
            if (
                len(parts) == 5
                and parts[:3] == ["api", "v1", "projects"]
                and parts[4] == "tasks"
                and parts[3].isdigit()
            ):
                pid = int(parts[3])
                if pid not in state.projects:
                    return self._send(404, {"error": "not found"})
                with state.lock:
                    state.next_task += 1
                    task = {
                        "id": state.next_task,
                        "project_id": pid,
                        "title": body.get("title", ""),
                        "status": "open",
                        "assignee": None,
                    }
                    state.tasks[pid].append(task)
                return self._send(201, task)
            return self._send(404, {"error": "not found"})

    return Handler


def serve(port: int = 8765, ttl: int = 300, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(State(ttl)))
    server.daemon_threads = True
    return server


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--ttl", type=int, default=300, help="access token lifetime in seconds")
    args = ap.parse_args()
    server = serve(args.port, args.ttl)
    print(f"demo API listening on http://127.0.0.1:{args.port} (login: demo / demo-password)")
    server.serve_forever()


if __name__ == "__main__":
    main()
