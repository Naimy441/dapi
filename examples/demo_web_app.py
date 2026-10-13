"""A Django-style demo web app: cookie sessions + CSRF (no bearer tokens).

  * GET  /login            HTML form; sets a ``csrftoken`` cookie and embeds the same token in the form
  * POST /login            form: username, password, csrfmiddlewaretoken -> sets HttpOnly ``sessionid``, 302
  * GET  /api/profile      JSON, requires the ``sessionid`` cookie
  * GET  /api/notes        JSON list;  POST /api/notes requires header X-CSRFToken == csrftoken cookie
  * GET  /api/notes/{id}
  * POST /logout

Run:  python examples/demo_web_app.py --port 8766    (login: alice / wonderland)
"""

from __future__ import annotations

import argparse
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

USERS = {"alice": {"password": "wonderland", "id": 1, "name": "Alice"}}


class WebState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.sessions: dict[str, int] = {}
        self.notes = {
            1: {"id": 1, "title": "Groceries", "body": "milk", "pinned": True},
            2: {"id": 2, "title": "Ideas", "body": "tea party", "pinned": False},
        }


def make_handler(state: WebState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "DemoWeb/1.0"

        def log_message(self, fmt, *args):
            pass

        def _cookies(self) -> dict[str, str]:
            out = {}
            for part in (self.headers.get("Cookie") or "").split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    out[k] = v
            return out

        def _send(self, status: int, body=None, ctype="application/json", headers=None):
            data = (json.dumps(body) if ctype == "application/json" else body or "").encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in headers or []:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _user(self) -> int | None:
            return state.sessions.get(self._cookies().get("sessionid", ""))

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/login":
                token = secrets.token_hex(16)
                html = (
                    "<form method=post action=/login>"
                    f"<input type=hidden name=csrfmiddlewaretoken value={token}>"
                    "<input name=username><input name=password type=password></form>"
                )
                return self._send(
                    200, html, "text/html", [("Set-Cookie", f"csrftoken={token}; Path=/; SameSite=Lax")]
                )
            uid = self._user()
            if uid is None:
                return self._send(403, {"detail": "Authentication credentials were not provided."})
            if path == "/api/profile":
                user = next(u for u in USERS.values() if u["id"] == uid)
                return self._send(200, {"id": uid, "name": user["name"]})
            if path == "/api/notes":
                return self._send(200, list(state.notes.values()))
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[:2] == ["api", "notes"] and parts[2].isdigit():
                note = state.notes.get(int(parts[2]))
                return self._send(200, note) if note else self._send(404, {"detail": "Not found."})
            return self._send(404, {"detail": "Not found."})

        def do_POST(self):
            path = urlsplit(self.path).path
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            cookies = self._cookies()
            if path == "/login":
                form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                if not cookies.get("csrftoken") or form.get("csrfmiddlewaretoken") != cookies["csrftoken"]:
                    return self._send(403, {"detail": "CSRF verification failed."})
                user = USERS.get(form.get("username", ""))
                if not user or user["password"] != form.get("password"):
                    return self._send(200, "<p>Invalid login</p>", "text/html")
                sid = secrets.token_hex(20)
                with state.lock:
                    state.sessions[sid] = user["id"]
                return self._send(
                    302,
                    "",
                    "text/html",
                    [
                        ("Location", "/"),
                        ("Set-Cookie", f"sessionid={sid}; Path=/; HttpOnly; Max-Age=1209600"),
                    ],
                )
            if self._user() is None:
                return self._send(403, {"detail": "Authentication credentials were not provided."})
            if self.headers.get("X-CSRFToken") != cookies.get("csrftoken"):
                return self._send(403, {"detail": "CSRF Failed: CSRF token missing."})
            if path == "/logout":
                state.sessions.pop(cookies.get("sessionid", ""), None)
                return self._send(204, "", "text/html")
            if path == "/api/notes":
                body = json.loads(raw or b"{}")
                with state.lock:
                    note = {
                        "id": max(state.notes) + 1,
                        "title": body.get("title", ""),
                        "body": body.get("body", ""),
                        "pinned": False,
                    }
                    state.notes[note["id"]] = note
                return self._send(201, note)
            return self._send(404, {"detail": "Not found."})

    return Handler


def serve(port: int = 8766, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(WebState()))
    server.daemon_threads = True
    return server


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8766)
    args = ap.parse_args()
    print(f"demo web app on http://127.0.0.1:{args.port} (login: alice / wonderland)")
    serve(args.port).serve_forever()


if __name__ == "__main__":
    main()
