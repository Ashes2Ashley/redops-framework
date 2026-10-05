"""Append-only record of every outbound request, including cache hits."""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    tool        TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    url         TEXT    NOT NULL,
    status      INTEGER,
    elapsed_ms  INTEGER,
    from_cache  INTEGER NOT NULL DEFAULT 0,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts  ON audit(ts);
CREATE INDEX IF NOT EXISTS audit_url ON audit(url);
"""


class AuditLog:
    def __init__(self, path=":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def record(self, *, tool, method, url, status=None, elapsed_ms=None,
               from_cache=False, error=None):
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (ts, tool, method, url, status, elapsed_ms,"
                " from_cache, error) VALUES (?,?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 tool, method, url, status, elapsed_ms, int(from_cache), error))
            self._conn.commit()

    def requests_for(self, tool):
        return self._conn.execute(
            "SELECT ts, method, url, status FROM audit WHERE tool=? ORDER BY id",
            (tool,)).fetchall()

    def count(self):
        return self._conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]

    def close(self):
        self._conn.close()
