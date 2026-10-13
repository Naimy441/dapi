"""Workspace: the ``.dapi/`` directory holding the flow database, vault and config."""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from dapi.models import RawExchange, header_get, media_type, split_url
from dapi.redact import Redactor
from dapi.store import Store
from dapi.vault import Vault, load_or_create_key

log = logging.getLogger("dapi")

STATIC_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp4",
    ".webm",
    ".mp3",
    ".wasm",
)
STATIC_TYPES = (
    "image/",
    "font/",
    "video/",
    "audio/",
    "text/css",
    "application/javascript",
    "text/javascript",
    "application/wasm",
)
GITIGNORE = "# dapi workspace: contains captured traffic and encrypted credentials. Never commit.\n*\n"


@dataclass
class Config:
    scope: list[str] = field(default_factory=list)  # host glob patterns; empty = record everything
    ignore_hosts: list[str] = field(default_factory=list)
    record_static: bool = False
    max_body_bytes: int = 512 * 1024
    extra_secret_keys: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> Config:
        if not path.exists():
            return cls()
        data = json.loads(path.read_text())
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2) + "\n")


def host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower()
    for pat in patterns:
        pat = pat.lower().strip()
        if fnmatch.fnmatch(host, pat) or (pat.startswith("*.") and host == pat[2:]):
            return True
    return False


def find_home(start: Path | None = None) -> Path:
    """Locate the workspace: $DAPI_HOME, else the nearest ``.dapi`` dir upwards, else ``./.dapi``."""
    env = os.environ.get("DAPI_HOME")
    if env:
        return Path(env).expanduser().resolve()
    cur = (start or Path.cwd()).resolve()
    for candidate in (cur, *cur.parents):
        if (candidate / ".dapi").is_dir():
            return candidate / ".dapi"
    return cur / ".dapi"


class Workspace:
    """Entry point to everything dapi stores. Cheap to construct; safe to share across threads."""

    def __init__(self, home: Path | str | None = None):
        self.home = Path(home).expanduser().resolve() if home else find_home()
        self.home.mkdir(parents=True, exist_ok=True)
        os.chmod(self.home, 0o700)
        gi = self.home / ".gitignore"
        if not gi.exists():
            gi.write_text(GITIGNORE)
        self.config_path = self.home / "config.json"
        self.config = Config.load(self.config_path)
        if not self.config_path.exists():
            self.config.save(self.config_path)
        self.store = Store(self.home / "dapi.db")
        key, source = load_or_create_key(self.home, self.store)
        self.vault = Vault(self.store, key, source)
        self.redactor = Redactor(self.vault, self.config.max_body_bytes, self.config.extra_secret_keys)
        self._ingest_lock = threading.Lock()
        self._cache: dict[str, tuple[Any, Any]] = {}
        self._skipped_hosts: set[str] = set()

    def __repr__(self) -> str:
        return f"Workspace({str(self.home)!r})"

    # -- config ----------------------------------------------------------------------------
    def save_config(self) -> None:
        self.config.save(self.config_path)

    def in_scope(self, host: str) -> bool:
        if self.config.ignore_hosts and host_matches(host, self.config.ignore_hosts):
            return False
        return not self.config.scope or host_matches(host, self.config.scope)

    def is_static(self, raw: RawExchange) -> bool:
        _, _, _, path, _ = split_url(raw.url)
        if path.lower().endswith(STATIC_EXTENSIONS):
            return True
        ct = media_type(header_get(raw.resp_headers, "content-type"))
        return ct.startswith(STATIC_TYPES)

    # -- ingest ----------------------------------------------------------------------------
    def ingest(self, raw: RawExchange, force: bool = False) -> int | None:
        """Redact and store one exchange. Returns the flow id, or None if filtered out."""
        _, host, _, _, _ = split_url(raw.url)
        if not force:
            if not self.in_scope(host):
                if host not in self._skipped_hosts:
                    self._skipped_hosts.add(host)
                    log.info("ignoring %s: outside scope %s", host, self.config.scope)
                return None
            if not self.config.record_static and self.is_static(raw):
                return None
            if raw.method.upper() == "CONNECT":
                return None
        with self._ingest_lock:
            ex, sightings = self.redactor.redact(raw)
            flow_id = self.store.add_exchange(ex, sightings)
        log.info("recorded #%s %s %s%s -> %s", flow_id, ex.method, ex.origin, ex.path, ex.status)
        return flow_id

    # -- cached analysis -------------------------------------------------------------------
    def cached(self, key: str, compute):
        """Memoize an analysis result until new flows arrive."""
        rev = self.store.revision()
        hit = self._cache.get(key)
        if hit and hit[0] == rev:
            return hit[1]
        value = compute()
        self._cache[key] = (rev, value)
        return value

    def invalidate(self) -> None:
        self._cache.clear()
        self.vault.invalidate()
