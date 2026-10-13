"""dapi command line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import shutil
import subprocess
import sys
from typing import Any

from dapi import __version__
from dapi.service import DapiError


def _print(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def _table(rows: list[list[str]], headers: list[str]) -> None:
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows, strict=False)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[str(x) for x in r]))


def _service(args: argparse.Namespace):
    from dapi.service import DapiService
    from dapi.workspace import Workspace

    return DapiService(Workspace(args.home))


def cmd_init(args: argparse.Namespace) -> None:
    from dapi.workspace import Workspace

    ws = Workspace(args.home or os.path.join(os.getcwd(), ".dapi"))
    if args.scope:
        ws.config.scope = args.scope
        ws.save_config()
    print(f"Initialized dapi workspace at {ws.home}")
    print(f"  scope: {ws.config.scope or 'everything (use --scope to restrict)'}")
    print(f"  vault key: {ws.vault.key_source}")
    print(
        "Next: `dapi capture --scope api.example.com` or `dapi import traffic.har`, then `dapi mcp-config`."
    )


def cmd_capture(args: argparse.Namespace) -> None:
    from dapi.capture.runner import run_foreground, setup_hints
    from dapi.workspace import Workspace

    ws = Workspace(args.home)
    if args.scope:
        ws.config.scope = args.scope
        ws.save_config()
    hints = setup_hints(args.listen_host, args.port, args.mode)
    print(f"dapi: recording into {ws.home} (scope: {ws.config.scope or 'everything'})", file=sys.stderr)
    for h in hints["how_to_route_traffic"]:
        print(f"  - {h}", file=sys.stderr)
    extra = (["--ssl-insecure"] if args.ssl_insecure else []) + list(args.mitm_args or [])
    sys.exit(run_foreground(ws, args.port, args.scope, args.mode, args.listen_host, extra))


def cmd_import(args: argparse.Namespace) -> None:
    _print(_service(args).traffic_import(args.path))


def cmd_status(args: argparse.Namespace) -> None:
    _print(_service(args).status())


def cmd_flows(args: argparse.Namespace) -> None:
    svc = _service(args)
    if args.flow_id is not None:
        _print(svc.traffic_get(args.flow_id, args.max_body))
        return
    data = svc.traffic_list(
        origin=args.origin, endpoint_id=args.endpoint, limit=args.limit, offset=args.offset
    )
    if args.json:
        _print(data)
        return
    _table(
        [[f["id"], f["method"], f["status"], f["url"][:100], f["source"]] for f in data["flows"]],
        ["#", "METHOD", "STATUS", "URL", "SOURCE"],
    )
    print(f"\n{data['total']} flows")


def cmd_endpoints(args: argparse.Namespace) -> None:
    data = _service(args).endpoints_discover(args.origin)
    if args.json:
        _print(data)
        return
    _table(
        [
            [
                e["id"],
                e["method"],
                e["origin"] + e["path"],
                e["auth"],
                ",".join(e["statuses"]),
                e["flows"],
                "ro" if e["read_only"] else "",
                ",".join(e.get("tags", [])),
            ]
            for e in data["endpoints"]
        ],
        ["ID", "METHOD", "ENDPOINT", "AUTH", "STATUS", "FLOWS", "RO", "TAGS"],
    )


def cmd_endpoint(args: argparse.Namespace) -> None:
    _print(_service(args).endpoint_get(args.endpoint_id))


def cmd_auth(args: argparse.Namespace) -> None:
    data = _service(args).auth_analyze(args.origin)
    if args.json:
        _print(data)
        return
    origins = {data["origin"]: data} if "origin" in data else data.get("origins", {})
    for origin, model in origins.items():
        print(f"== {origin}")
        for note in model.get("notes", []):
            print(f"  - {note}")
        print(f"  endpoint auth: {model.get('endpoint_auth_summary')}")


def cmd_deps(args: argparse.Namespace) -> None:
    _print(_service(args).dependencies_discover(args.endpoint, args.origin))


def cmd_verify(args: argparse.Namespace) -> None:
    _print(
        _service(args).session_verify(
            args.origin,
            args.endpoint or None,
            args.probe_auth,
            not args.no_refresh,
            args.allow_login,
            args.max,
        )
    )


def cmd_refresh(args: argparse.Namespace) -> None:
    _print(_service(args).session_refresh(args.origin, args.allow_login))


def cmd_generate(args: argparse.Namespace) -> None:
    _print(
        _service(args).client_generate(
            args.origin, args.lang, args.output, args.endpoint or None, args.class_name
        )
    )


def cmd_docs(args: argparse.Namespace) -> None:
    res = _service(args).docs_generate(args.origin, args.format, args.output)
    print(res["path"] or res["content"])


def cmd_creds(args: argparse.Namespace) -> None:
    svc = _service(args)
    if args.action == "list":
        _print(svc.credentials_list(args.origin))
    elif args.action == "delete":
        if not args.ref:
            sys.exit("usage: dapi creds delete <ref>")
        print("deleted" if svc.ws.vault.delete(args.ref) else "not found")


def _read_value(spec: str, sep: str) -> tuple[str, str]:
    name, _, value = spec.partition(sep)
    name, value = name.strip(), value.strip()
    if value in ("", "-"):
        value = getpass.getpass(f"value for {name} (input hidden): ")
    return name, value


def cmd_session(args: argparse.Namespace) -> None:
    from dapi.analysis import analyze
    from dapi.session import current_session, match_origin, set_manual_session

    svc = _service(args)
    ws = svc.ws
    if args.action == "set":
        if not args.origin:
            sys.exit("--origin is required, e.g. --origin https://api.example.com")
        headers = dict(_read_value(h, ":") for h in args.header or [])
        cookies = dict(_read_value(c, "=") for c in args.cookie or [])
        sess = set_manual_session(ws, args.origin.rstrip("/"), headers, cookies)
        _print(ws.vault.scrub_obj(sess.describe(ws.vault)))
    else:
        a = analyze(ws)
        origin = match_origin(a, args.origin)
        sess = current_session(ws, a, origin)
        _print(ws.vault.scrub_obj(sess.describe(ws.vault)) if sess else {"origin": origin, "session": None})


def cmd_run(args: argparse.Namespace) -> None:
    """Run a command with the captured session exported as <PREFIX>_* environment variables."""
    from dapi.analysis import analyze
    from dapi.codegen.spec import build_spec
    from dapi.session import match_origin, resolve_session

    svc = _service(args)
    a = analyze(svc.ws)
    origin = match_origin(a, args.origin)
    spec = build_spec(a, origin)
    sess = resolve_session(svc.ws, origin)
    prefix = args.prefix or spec.env_prefix
    env = dict(os.environ)
    headers = dict(sess["headers"])
    if spec.auth.header_name:
        for name in list(headers):
            if name.lower() == spec.auth.header_name.lower():
                value = headers.pop(name)
                env[f"{prefix}_TOKEN"] = (
                    value.split(" ", 1)[1] if spec.auth.scheme and " " in value else value
                )
    env[f"{prefix}_BASE_URL"] = origin
    if headers:
        env[f"{prefix}_HEADERS"] = json.dumps(headers)
    if sess["cookies"]:
        env[f"{prefix}_COOKIES"] = "; ".join(f"{k}={v}" for k, v in sess["cookies"].items())
    if sess.get("refresh_token"):
        env[f"{prefix}_REFRESH_TOKEN"] = sess["refresh_token"]
    cmd = [c for c in args.command if c != "--"]
    if not cmd:
        sys.exit("usage: dapi run [--origin X] -- <command> [args...]")
    print(f"dapi: running with session for {origin} in {prefix}_* env vars", file=sys.stderr)
    sys.exit(subprocess.call(cmd, env=env))


def cmd_mcp(args: argparse.Namespace) -> None:
    from dapi.mcp_server import main
    from dapi.workspace import Workspace

    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    main(Workspace(args.home))


def cmd_mcp_config(args: argparse.Namespace) -> None:
    dapi_exe = shutil.which("dapi")
    command, cmd_args = (dapi_exe, []) if dapi_exe else (sys.executable, ["-m", "dapi.cli"])
    if args.home:
        cmd_args += ["--home", os.path.abspath(args.home)]
    cmd_args.append("mcp")
    if args.client == "claude":
        print("claude mcp add dapi -- " + " ".join([command, *cmd_args]))
    elif args.client == "codex":
        print(
            f"# add to ~/.codex/config.toml\n[mcp_servers.dapi]\ncommand = {json.dumps(command)}\nargs = {json.dumps(cmd_args)}"
        )
    else:
        _print({"mcpServers": {"dapi": {"command": command, "args": cmd_args}}})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dapi", description="Evidence-grounded API reverse engineering (mitmproxy + MCP)."
    )
    p.add_argument("--home", help="workspace directory (default: nearest .dapi/ or $DAPI_HOME)")
    p.add_argument("--version", action="version", version=f"dapi {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create a .dapi workspace in the current directory")
    s.add_argument("--scope", action="append", help="host glob to record (repeatable)")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("capture", help="run the recording proxy in the foreground (Ctrl-C to stop)")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--listen-host", default="127.0.0.1")
    s.add_argument("--scope", action="append", help="host glob to record (repeatable)")
    s.add_argument(
        "--mode",
        help="mitmproxy mode, e.g. wireguard, reverse:https://api.example.com, upstream:http://host:port",
    )
    s.add_argument(
        "--ssl-insecure",
        action="store_true",
        help="don't verify upstream TLS certs (self-signed staging hosts)",
    )
    s.add_argument("mitm_args", nargs=argparse.REMAINDER, help="extra mitmdump arguments after --")
    s.set_defaults(fn=cmd_capture)

    s = sub.add_parser("import", help="import a HAR file or mitmproxy flow dump")
    s.add_argument("path")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("status", help="workspace overview")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("flows", help="list flows, or show one: dapi flows <id>")
    s.add_argument("flow_id", nargs="?", type=int)
    s.add_argument("--origin")
    s.add_argument("--endpoint")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--max-body", type=int, default=4000)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_flows)

    s = sub.add_parser("endpoints", help="show the endpoint catalog")
    s.add_argument("--origin")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_endpoints)

    s = sub.add_parser("endpoint", help="details for one endpoint")
    s.add_argument("endpoint_id")
    s.set_defaults(fn=cmd_endpoint)

    s = sub.add_parser("auth", help="authentication flow analysis")
    s.add_argument("--origin")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_auth)

    s = sub.add_parser("deps", help="endpoint dependencies")
    s.add_argument("--endpoint")
    s.add_argument("--origin")
    s.set_defaults(fn=cmd_deps)

    s = sub.add_parser("verify", help="verify the session against read-only endpoints")
    s.add_argument("--origin")
    s.add_argument("--endpoint", action="append")
    s.add_argument("--probe-auth", action="store_true", help="also test without credentials / per credential")
    s.add_argument("--no-refresh", action="store_true")
    s.add_argument("--allow-login", action="store_true", help="permit replaying the observed login")
    s.add_argument("--max", type=int, default=3)
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("refresh", help="refresh credentials via the observed refresh (or login) flow")
    s.add_argument("--origin")
    s.add_argument("--allow-login", action="store_true")
    s.set_defaults(fn=cmd_refresh)

    s = sub.add_parser("generate", help="generate an API client")
    s.add_argument("--lang", default="python", choices=["python", "typescript", "py", "ts"])
    s.add_argument("--origin")
    s.add_argument("-o", "--output", help="output directory (default ./dapi_generated/clients)")
    s.add_argument("--endpoint", action="append")
    s.add_argument("--class-name")
    s.set_defaults(fn=cmd_generate)

    s = sub.add_parser("docs", help="generate OpenAPI or Markdown docs")
    s.add_argument("--format", default="openapi", choices=["openapi", "markdown"])
    s.add_argument("--origin")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_docs)

    s = sub.add_parser("creds", help="list or delete vaulted credentials (values are never shown)")
    s.add_argument("action", choices=["list", "delete"])
    s.add_argument("ref", nargs="?")
    s.add_argument("--origin")
    s.set_defaults(fn=cmd_creds)

    s = sub.add_parser(
        "session", help="show the current session, or set one manually (values prompted, hidden)"
    )
    s.add_argument("action", choices=["show", "set"])
    s.add_argument("--origin")
    s.add_argument("--header", action="append", help="'Name: value' or 'Name' to be prompted")
    s.add_argument("--cookie", action="append", help="'name=value' or 'name' to be prompted")
    s.set_defaults(fn=cmd_session)

    s = sub.add_parser("run", help="run a command with the session exported as <PREFIX>_* env vars")
    s.add_argument("--origin")
    s.add_argument("--prefix")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("mcp", help="run the MCP server (stdio)")
    s.set_defaults(fn=cmd_mcp)

    s = sub.add_parser("mcp-config", help="print MCP configuration for an agent")
    s.add_argument("--client", default="claude", choices=["claude", "codex", "json"])
    s.set_defaults(fn=cmd_mcp_config)
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.verbose:
        logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    if getattr(args, "mitm_args", None) and args.mitm_args[:1] == ["--"]:
        args.mitm_args = args.mitm_args[1:]
    try:
        args.fn(args)
    except (KeyError, LookupError, ValueError, RuntimeError, DapiError) as exc:
        sys.exit(f"dapi: {exc.args[0] if exc.args else exc}")


if __name__ == "__main__":
    main()
