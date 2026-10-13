"""JSON Schema inference from observed samples, plus a light conformance checker."""

from __future__ import annotations

import re
from typing import Any

from dapi.vault import PLACEHOLDER_RE

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
URI_RE = re.compile(r"^https?://\S+$")
MAX_PROPERTIES = 150
MAP_KEY_RE = re.compile(r"^([0-9]+|[0-9a-fA-F-]{16,})$")


def _string_format(value: str) -> str | None:
    if PLACEHOLDER_RE.fullmatch(value):
        return "x-secret"
    if UUID_RE.match(value):
        return "uuid"
    if DATETIME_RE.match(value):
        return "date-time"
    if DATE_RE.match(value):
        return "date"
    if EMAIL_RE.match(value):
        return "email"
    if URI_RE.match(value):
        return "uri"
    return None


def infer(value: Any, depth: int = 0) -> dict[str, Any]:
    """Infer an internal schema node for a single JSON value."""
    if depth > 12:
        return {}
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        node: dict[str, Any] = {"type": "string"}
        fmt = _string_format(value)
        if fmt == "x-secret":
            node["x-dapi-secret"] = True
        elif fmt:
            node["format"] = fmt
        return node
    if isinstance(value, list):
        items: dict[str, Any] | None = None
        for item in value[:100]:
            items = infer(item, depth + 1) if items is None else merge(items, infer(item, depth + 1))
        return {"type": "array", "items": items or {}}
    if isinstance(value, dict):
        if len(value) > 20 and all(MAP_KEY_RE.match(str(k)) for k in value):
            vals: dict[str, Any] | None = None
            for v in list(value.values())[:100]:
                vals = infer(v, depth + 1) if vals is None else merge(vals, infer(v, depth + 1))
            return {"type": "object", "additionalProperties": vals or {}}
        props = {str(k): infer(v, depth + 1) for k, v in list(value.items())[:MAX_PROPERTIES]}
        return {"type": "object", "properties": props, "required": sorted(props)}
    return {}


def _variants(node: dict[str, Any]) -> list[dict[str, Any]]:
    return list(node["anyOf"]) if "anyOf" in node else [node]


def merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Merge two schema nodes into one that accepts both."""
    if not a:
        return b
    if not b:
        return a
    variants = _variants(a)
    for vb in _variants(b):
        for i, va in enumerate(variants):
            merged = _merge_same(va, vb)
            if merged is not None:
                variants[i] = merged
                break
        else:
            variants.append(vb)
    if len(variants) == 1:
        return variants[0]
    variants.sort(key=lambda v: (v.get("type") == "null", str(v.get("type"))))
    return {"anyOf": variants}


def _merge_same(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any] | None:
    ta, tb = a.get("type"), b.get("type")
    if {ta, tb} == {"integer", "number"}:
        return {"type": "number"}
    if ta != tb:
        return None
    if ta == "string":
        out = {"type": "string"}
        if a.get("format") and a.get("format") == b.get("format"):
            out["format"] = a["format"]
        if a.get("x-dapi-secret") and b.get("x-dapi-secret"):
            out["x-dapi-secret"] = True
        return out
    if ta == "array":
        return {"type": "array", "items": merge(a.get("items", {}), b.get("items", {}))}
    if ta == "object":
        if "additionalProperties" in a or "additionalProperties" in b:
            ap = merge(a.get("additionalProperties", {}), b.get("additionalProperties", {}))
            for node in (a, b):
                for v in node.get("properties", {}).values():
                    ap = merge(ap, v)
            return {"type": "object", "additionalProperties": ap}
        pa, pb = a.get("properties", {}), b.get("properties", {})
        props = dict(pa)
        for k, v in pb.items():
            props[k] = merge(props[k], v) if k in props else v
        required = sorted(set(a.get("required", [])) & set(b.get("required", [])))
        return {"type": "object", "properties": props, "required": required}
    return dict(a)


class SchemaBuilder:
    """Accumulates samples and emits a JSON Schema (draft 2020-12 compatible)."""

    def __init__(self) -> None:
        self.node: dict[str, Any] = {}
        self.samples = 0

    def add(self, value: Any) -> None:
        self.samples += 1
        self.node = merge(self.node, infer(value))

    def schema(self) -> dict[str, Any]:
        if not self.samples:
            return {}
        out = finalize(self.node)
        out["x-dapi-samples"] = self.samples
        return out


def finalize(node: dict[str, Any]) -> dict[str, Any]:
    """Convert internal nodes to tidy JSON Schema (nullable unions become type arrays)."""
    if "anyOf" in node:
        variants = [finalize(v) for v in node["anyOf"]]
        non_null = [v for v in variants if v.get("type") != "null"]
        if len(non_null) == 1 and len(variants) == 2 and isinstance(non_null[0].get("type"), str):
            out = dict(non_null[0])
            out["type"] = [out["type"], "null"]
            return out
        return {"anyOf": variants}
    out = dict(node)
    if out.get("type") == "object":
        if "properties" in out:
            out["properties"] = {k: finalize(v) for k, v in out["properties"].items()}
            if not out.get("required"):
                out.pop("required", None)
        if "additionalProperties" in out and isinstance(out["additionalProperties"], dict):
            out["additionalProperties"] = finalize(out["additionalProperties"])
    if out.get("type") == "array" and isinstance(out.get("items"), dict):
        out["items"] = finalize(out["items"])
    return out


def _types_of(schema: dict[str, Any]) -> set[str]:
    t = schema.get("type")
    if isinstance(t, list):
        return set(t)
    return {t} if t else set()


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def check(
    schema: dict[str, Any], value: Any, path: str = "$", depth: int = 0, issues: list[str] | None = None
) -> list[str]:
    """Return human-readable differences between ``value`` and an inferred ``schema``.

    Deliberately lenient: inferred schemas are evidence summaries, not contracts.
    Reports type mismatches and missing always-present keys up to a few levels deep.
    """
    issues = [] if issues is None else issues
    if not schema or depth > 6 or len(issues) > 20:
        return issues
    if "anyOf" in schema:
        if not any(not check(s, value, path, depth + 1, []) for s in schema["anyOf"]):
            issues.append(f"{path}: value of type {_json_type(value)} matches none of the observed variants")
        return issues
    types = _types_of(schema)
    actual = _json_type(value)
    if types and actual not in types and not (actual == "integer" and "number" in types):
        issues.append(f"{path}: expected {'/'.join(sorted(types))}, got {actual}")
        return issues
    if actual == "object":
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                issues.append(f"{path}: missing key '{key}' (present in every observed sample)")
        for key, sub in props.items():
            if key in value:
                check(sub, value[key], f"{path}.{key}", depth + 1, issues)
    elif actual == "array" and schema.get("items"):
        for item in value[:5]:
            check(schema["items"], item, f"{path}[]", depth + 1, issues)
    return issues
