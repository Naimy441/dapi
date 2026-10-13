"""dapi: evidence-grounded API reverse engineering for AI agents.

Capture authorized traffic with mitmproxy (or import HAR files), build an API
catalog, map authentication flows, verify sessions against read-only
endpoints and generate typed API clients -- all exposed over MCP.
"""

__version__ = "0.1.0"

from dapi.workspace import Workspace  # noqa: E402

__all__ = ["Workspace", "__version__"]
