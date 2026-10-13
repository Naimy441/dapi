"""Turn inferred JSON Schemas into named model types (shared by the Python and TS generators)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from dapi.codegen.spec import pascal

MAX_DEPTH = 5


def item_name(hint: str) -> str:
    """Name for array elements: ``ListProjectsResponseItems`` -> ``ListProjectsResponseItem``."""
    if hint.endswith("ies") and len(hint) > 4:
        return hint[:-3] + "y"
    if hint.endswith("s") and not hint.endswith("ss") and len(hint) > 3:
        return hint[:-1]
    return hint + "Item"


@dataclass
class Model:
    name: str
    fields: list[tuple[str, Any, bool]]  # (key, type node, required)


@dataclass
class TypeRegistry:
    """Collects object models, deduplicating structurally identical ones."""

    models: list[Model] = field(default_factory=list)
    by_signature: dict[str, str] = field(default_factory=dict)
    names: set[str] = field(default_factory=set)

    def _unique(self, name: str) -> str:
        base, n = name, 2
        while name in self.names:
            name, n = f"{base}{n}", n + 1
        self.names.add(name)
        return name

    def node(self, schema: dict[str, Any], hint: str, depth: int = 0) -> Any:
        """Return a language-neutral type node: ("prim", t) | ("list", node) | ("map", node) |
        ("union", [nodes]) | ("model", name) | ("any",)."""
        if not schema or depth > MAX_DEPTH:
            return ("any",)
        if "anyOf" in schema:
            return ("union", [self.node(s, hint, depth + 1) for s in schema["anyOf"]])
        t = schema.get("type")
        if isinstance(t, list):
            return ("union", [self.node({**schema, "type": x}, hint, depth + 1) for x in t])
        if t in {"string", "integer", "number", "boolean", "null"}:
            return ("prim", t)
        if t == "array":
            return ("list", self.node(schema.get("items") or {}, item_name(hint), depth + 1))
        if t == "object":
            if "additionalProperties" in schema and not schema.get("properties"):
                return ("map", self.node(schema["additionalProperties"] or {}, hint + "Value", depth + 1))
            props = schema.get("properties") or {}
            if not props:
                return ("map", ("any",))
            required = set(schema.get("required") or [])
            model_name = pascal(hint)
            fields = [
                (k, self.node(v, model_name + pascal(k), depth + 1), k in required) for k, v in props.items()
            ]
            sig = json.dumps([(k, repr(n), r) for k, n, r in fields])
            if sig in self.by_signature:
                return ("model", self.by_signature[sig])
            name = self._unique(model_name)
            self.by_signature[sig] = name
            self.models.append(Model(name, fields))
            return ("model", name)
        return ("any",)
