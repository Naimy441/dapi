"""Analysis pipeline: flows -> catalog -> auth model -> dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from dapi.analysis.auth import AuthContext, analyze_auth
from dapi.analysis.catalog import Catalog, Endpoint, build_catalog
from dapi.analysis.deps import discover_dependencies

if TYPE_CHECKING:
    from dapi.workspace import Workspace


@dataclass
class Analysis:
    catalog: Catalog
    ctx: AuthContext
    auth: dict[str, Any]

    def endpoint(self, endpoint_id: str) -> Endpoint:
        ep = self.catalog.get(endpoint_id)
        if ep is None:
            raise KeyError(f"unknown endpoint {endpoint_id!r}; call endpoints_discover to list endpoint ids")
        return ep

    def dependencies(self, endpoint_id: str | None = None, origin: str | None = None) -> dict[str, Any]:
        return discover_dependencies(self.ctx, endpoint_id, origin)

    def auth_for(self, origin: str) -> dict[str, Any]:
        return self.auth["origins"].get(origin, {})


def analyze(ws: Workspace) -> Analysis:
    """Run (or fetch from cache) the full analysis over every stored flow."""

    def compute() -> Analysis:
        flows = list(ws.store.iter_flows())
        catalog = build_catalog(flows)
        ctx = AuthContext.build(flows, catalog, ws.store.all_sightings(), ws.vault)
        auth = analyze_auth(ctx)
        return Analysis(catalog, ctx, auth)

    return ws.cached("analysis", compute)


__all__ = ["Analysis", "analyze", "Catalog", "Endpoint"]
