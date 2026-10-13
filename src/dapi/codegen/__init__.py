"""Client and documentation generators."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dapi.analysis import Analysis
from dapi.codegen.docs import generate_markdown, generate_openapi
from dapi.codegen.python import generate_python
from dapi.codegen.spec import ClientSpec, build_spec, snake
from dapi.codegen.typescript import generate_typescript

LANGUAGES = {"python": (".py", generate_python), "typescript": (".ts", generate_typescript)}


def generate_client(
    analysis: Analysis,
    origin: str,
    language: str,
    output_dir: Path,
    endpoint_ids: list[str] | None = None,
    class_name: str | None = None,
    flow_count: int = 0,
) -> dict[str, Any]:
    lang = {"py": "python", "ts": "typescript"}.get(language.lower(), language.lower())
    if lang not in LANGUAGES:
        raise ValueError(f"unsupported language {language!r}; choose one of {sorted(LANGUAGES)}")
    spec = build_spec(analysis, origin, endpoint_ids, class_name, flow_count)
    ext, gen = LANGUAGES[lang]
    code = gen(spec)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{snake(spec.title)}_client{ext}"
    path.write_text(code)
    return {
        "path": str(path),
        "language": lang,
        "class_name": spec.class_name,
        "env_prefix": spec.env_prefix,
        "auth": {
            "kind": spec.auth.kind,
            "header": spec.auth.header_name,
            "scheme": spec.auth.scheme,
            "cookies": spec.auth.cookie_names,
            "query_param": spec.auth.query_name,
            "login": f"{spec.auth.login.method} {spec.auth.login.path}" if spec.auth.login else None,
            "refresh": f"{spec.auth.refresh.method} {spec.auth.refresh.path}" if spec.auth.refresh else None,
        },
        "methods": [
            {
                "name": o.name,
                "endpoint": f"{o.method} {o.path}",
                "endpoint_id": o.endpoint_id,
                "auth": o.auth_required,
            }
            for o in spec.operations
        ],
        "lines": code.count("\n"),
    }


def generate_docs(
    analysis: Analysis, origin: str, fmt: str, output_path: Path | None, flow_count: int = 0
) -> dict[str, Any]:
    if fmt == "openapi":
        content = json.dumps(generate_openapi(analysis, origin, flow_count), indent=2)
    elif fmt == "markdown":
        content = generate_markdown(analysis, origin, flow_count)
    else:
        raise ValueError("format must be 'openapi' or 'markdown'")
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)
    return {
        "path": str(output_path) if output_path else None,
        "format": fmt,
        "content": None if output_path else content,
    }


__all__ = [
    "ClientSpec",
    "build_spec",
    "generate_client",
    "generate_docs",
    "generate_python",
    "generate_typescript",
]
