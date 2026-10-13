"""SQLite persistence for redacted flows, encrypted secrets and their sightings."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dapi.models import Exchange

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    method TEXT NOT NULL,
    scheme TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    path TEXT NOT NULL,
    query TEXT NOT NULL,
    req_headers TEXT NOT NULL,
    req_body TEXT,
    req_ct TEXT,
    status INTEGER,
    resp_headers TEXT NOT NULL,
    resp_body TEXT,
    resp_ct TEXT,
    duration_ms REAL,
    source TEXT,
    error TEXT,
    req_size INTEGER DEFAULT 0,
    resp_size INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS flows_host ON flows(host);
CREATE TABLE IF NOT EXISTS secrets (
    ref TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    meta TEXT NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sightings (
    ref TEXT NOT NULL,
    flow_id INTEGER NOT NULL,
    side TEXT NOT NULL,
    location TEXT NOT NULL,
    PRIMARY KEY (ref, flow_id, side, location)
);
CREATE INDEX IF NOT EXISTS sightings_flow ON sightings(flow_id);
CREATE TABLE IF NOT EXISTS sessions (
    origin TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass
class Sighting:
    ref: str
    flow_id: int
    side: str  # "request" | "response"
    location: str  # e.g. "header:Authorization", "cookie:sid", "body:$.access_token"


class Store:
    """Thread-safe wrapper around the workspace SQLite database (WAL mode)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- flows -------------------------------------------------------------------------
    def add_exchange(self, ex: Exchange, sightings: Iterable[tuple[str, str, str]] = ()) -> int:
        """Insert a redacted exchange and its secret sightings ``(ref, side, location)``."""
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO flows (ts, method, scheme, host, port, path, query, req_headers, req_body,
                   req_ct, status, resp_headers, resp_body, resp_ct, duration_ms, source, error, req_size,
                   resp_size) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ex.ts,
                    ex.method,
                    ex.scheme,
                    ex.host,
                    ex.port,
                    ex.path,
                    json.dumps(ex.query),
                    json.dumps(ex.req_headers),
                    ex.req_body,
                    ex.req_content_type,
                    ex.status,
                    json.dumps(ex.resp_headers),
                    ex.resp_body,
                    ex.resp_content_type,
                    ex.duration_ms,
                    ex.source,
                    ex.error,
                    ex.req_size,
                    ex.resp_size,
                ),
            )
            flow_id = int(cur.lastrowid)
            self._conn.executemany(
                "INSERT OR IGNORE INTO sightings (ref, flow_id, side, location) VALUES (?,?,?,?)",
                [(ref, flow_id, side, loc) for ref, side, loc in sightings],
            )
            self._conn.commit()
            ex.id = flow_id
            return flow_id

    @staticmethod
    def _row_to_exchange(row: sqlite3.Row) -> Exchange:
        return Exchange(
            id=row["id"],
            ts=row["ts"],
            method=row["method"],
            scheme=row["scheme"],
            host=row["host"],
            port=row["port"],
            path=row["path"],
            query=[tuple(p) for p in json.loads(row["query"])],
            req_headers=[tuple(p) for p in json.loads(row["req_headers"])],
            req_body=row["req_body"],
            req_content_type=row["req_ct"] or "",
            status=row["status"],
            resp_headers=[tuple(p) for p in json.loads(row["resp_headers"])],
            resp_body=row["resp_body"],
            resp_content_type=row["resp_ct"] or "",
            duration_ms=row["duration_ms"],
            source=row["source"],
            error=row["error"],
            req_size=row["req_size"] or 0,
            resp_size=row["resp_size"] or 0,
        )

    def get_flow(self, flow_id: int) -> Exchange | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM flows WHERE id=?", (flow_id,)).fetchone()
        return self._row_to_exchange(row) if row else None

    def iter_flows(self, host: str | None = None) -> Iterator[Exchange]:
        sql, args = "SELECT * FROM flows", ()
        if host:
            sql, args = sql + " WHERE host=?", (host,)
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY ts, id", args).fetchall()
        for row in rows:
            yield self._row_to_exchange(row)

    def flow_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]

    def revision(self) -> tuple[int, int]:
        """A cheap fingerprint that changes whenever flows are added or removed."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM flows").fetchone()
        return int(row[0]), int(row[1])

    def hosts(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT scheme, host, port, COUNT(*) AS n FROM flows GROUP BY scheme, host, port ORDER BY n DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def clear_flows(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM flows")
            self._conn.execute("DELETE FROM sightings")
            self._conn.commit()

    # -- sightings -----------------------------------------------------------------------
    def sightings(self, flow_id: int | None = None, ref: str | None = None) -> list[Sighting]:
        sql, args = "SELECT ref, flow_id, side, location FROM sightings", []
        clauses = []
        if flow_id is not None:
            clauses.append("flow_id=?")
            args.append(flow_id)
        if ref is not None:
            clauses.append("ref=?")
            args.append(ref)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY flow_id", args).fetchall()
        return [Sighting(r["ref"], r["flow_id"], r["side"], r["location"]) for r in rows]

    def all_sightings(self) -> list[Sighting]:
        return self.sightings()

    # -- secrets -------------------------------------------------------------------------
    def put_secret(self, ref: str, kind: str, ciphertext: bytes, meta: dict) -> bool:
        """Insert a secret if new. Returns True if it was inserted."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO secrets (ref, kind, ciphertext, meta, created) VALUES (?,?,?,?,?)",
                (ref, kind, ciphertext, json.dumps(meta), time.time()),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def update_secret_meta(self, ref: str, meta: dict) -> None:
        with self._lock:
            self._conn.execute("UPDATE secrets SET meta=? WHERE ref=?", (json.dumps(meta), ref))
            self._conn.commit()

    def get_secret(self, ref: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute("SELECT * FROM secrets WHERE ref=?", (ref,)).fetchone()

    def list_secrets(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM secrets ORDER BY created").fetchall()

    def delete_secret(self, ref: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM secrets WHERE ref=?", (ref,))
            self._conn.commit()
            return cur.rowcount > 0

    # -- sessions & kv -------------------------------------------------------------------
    def put_session(self, origin: str, data: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO sessions (origin, data, updated) VALUES (?,?,?)",
                (origin, json.dumps(data), time.time()),
            )
            self._conn.commit()

    def get_session(self, origin: str) -> tuple[dict, float] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data, updated FROM sessions WHERE origin=?", (origin,)
            ).fetchone()
        return (json.loads(row["data"]), row["updated"]) if row else None

    def delete_session(self, origin: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE origin=?", (origin,))
            self._conn.commit()

    def kv_get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def kv_set(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?,?)", (key, json.dumps(value))
            )
            self._conn.commit()
