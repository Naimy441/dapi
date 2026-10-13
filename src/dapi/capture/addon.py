"""mitmproxy addon that records redacted flows into a dapi workspace.

Usually started for you by ``dapi capture``. It can also be loaded into any
mitmproxy tool directly::

    mitmdump -s "$(python -c 'import dapi.capture.addon as a; print(a.__file__)')" \
        --set dapi_home=./.dapi --set dapi_scope=api.example.com

Note: run mitmproxy with ``flow_detail=0`` (``dapi capture`` does) so that
mitmproxy's own console output does not print unredacted URLs and headers.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from mitmproxy import ctx, http

if __package__ in (None, ""):  # loaded as a script via `mitmdump -s`
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from dapi.capture.convert import flow_to_raw  # noqa: E402
from dapi.workspace import Workspace  # noqa: E402

log = logging.getLogger("dapi.capture")


class DapiRecorder:
    def __init__(self, workspace: Workspace | None = None):
        self.ws = workspace
        self.recorded = 0

    def load(self, loader) -> None:
        loader.add_option("dapi_home", str, "", "Path to the dapi workspace directory (default: auto-detect)")
        loader.add_option(
            "dapi_scope", str, "", "Comma-separated host globs to record (overrides workspace config)"
        )

    def configure(self, updated) -> None:
        if self.ws is None or "dapi_home" in updated:
            home = getattr(ctx.options, "dapi_home", "") or None
            if self.ws is None or home:
                self.ws = Workspace(home)
        scope = getattr(ctx.options, "dapi_scope", "")
        if scope:
            self.ws.config.scope = [s.strip() for s in scope.split(",") if s.strip()]

    def response(self, flow: http.HTTPFlow) -> None:
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            self._record(flow)

    def _record(self, flow: http.HTTPFlow) -> None:
        if self.ws is None:
            return
        try:
            flow_id = self.ws.ingest(flow_to_raw(flow, source="mitmproxy"))
        except Exception as exc:  # never break the proxied app because of recording problems
            log.warning("dapi: failed to record flow: %s", type(exc).__name__)
            return
        if flow_id is not None:
            self.recorded += 1  # Workspace.ingest logs the redacted summary


addons = [DapiRecorder()]
