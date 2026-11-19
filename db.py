"""
db.py
=====
Thin SQLite persistence layer. Single file, single user, no ORM — deliberately
minimal. Two tables:

  scans     one row per (site, scan attempt): status + metadata + any error.
  findings  the normalized vulnerabilities, always reflecting the LATEST
            successful scan for each site.

Re-scanning a site replaces that site's findings so the dashboard never shows
stale duplicates.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site        TEXT NOT NULL,
    status      TEXT NOT NULL,              -- queued|running|success|partial|error
    started_at  REAL,
    finished_at REAL,
    wp_version  TEXT,
    target_ip   TEXT,
    error       TEXT,
    source      TEXT                        -- 'wpscan' | 'ingest'
);

CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER,
    site              TEXT NOT NULL,
    finding_kind      TEXT,
    component_type    TEXT,
    component_name    TEXT,
    component_version TEXT,
    title             TEXT,
    severity          TEXT,
    cvss              REAL,
    fixed_in          TEXT,
    cves              TEXT,                  -- json array
    refs              TEXT,                  -- json array
    created_at        REAL
);

-- Older databases had a narrower unique key (site, title, component_name),
-- which collided when a plugin and a theme shared a slug and a vuln title.
DROP INDEX IF EXISTS idx_findings_dedup;
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup_v2
    ON findings(site, component_type, component_name, title);
CREATE INDEX IF NOT EXISTS idx_findings_site     ON findings(site);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        self.init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self._conn() as c:
            c.executescript(_SCHEMA)

    # -- scans ------------------------------------------------------------- #
    def create_scan(self, site: str, status: str = "pending", source: str = "wpscan") -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO scans (site, status, started_at, source) VALUES (?,?,?,?)",
                (site, status, time.time(), source),
            )
            return cur.lastrowid

    def update_scan(self, scan_id: int, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._conn() as c:
            c.execute(f"UPDATE scans SET {cols} WHERE id = ?", (*fields.values(), scan_id))

    def delete_scan_if_status(self, scan_id: int, status: str) -> None:
        """Remove a scan row only if it is still in `status` (e.g. a 'queued'
        placeholder for a site the batch never reached)."""
        with self._conn() as c:
            c.execute("DELETE FROM scans WHERE id = ? AND status = ?", (scan_id, status))

    def latest_scan_status(self) -> dict[str, dict[str, Any]]:
        """Most recent scan row per site, keyed by site."""
        with self._conn() as c:
            rows = c.execute(
                """
                SELECT s.* FROM scans s
                JOIN (SELECT site, MAX(id) AS mx FROM scans GROUP BY site) latest
                  ON s.id = latest.mx
                """
            ).fetchall()
        return {r["site"].rstrip("/"): dict(r) for r in rows}

    # -- findings ---------------------------------------------------------- #
    def replace_findings(self, site: str, scan_id: int, findings: list[dict[str, Any]]) -> None:
        site = site.rstrip("/")
        now = time.time()
        with self._conn() as c:
            c.execute("DELETE FROM findings WHERE site = ?", (site,))
            # OR IGNORE: a report can legitimately repeat a finding (same
            # component + title); keep one instead of failing the whole save.
            c.executemany(
                """
                INSERT OR IGNORE INTO findings
                  (scan_id, site, finding_kind, component_type, component_name,
                   component_version, title, severity, cvss, fixed_in, cves, refs, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        scan_id, site, f.get("finding_kind"), f.get("component_type"),
                        f.get("component_name"), f.get("component_version"), f.get("title"),
                        f.get("severity"), f.get("cvss"), f.get("fixed_in"),
                        json.dumps(f.get("cves") or []), json.dumps(f.get("references") or []),
                        now,
                    )
                    for f in findings
                ],
            )

    def add_finding_live(self, site: str, scan_id: int, f: dict[str, Any]) -> None:
        """Insert a single finding immediately as it's discovered during a live scan.
        Existing findings for the same site are NOT cleared first — replace_findings
        is called at the end of the scan to produce the final clean set. This method
        is purely for making findings appear in the UI table in real time."""
        site = site.rstrip("/")
        with self._conn() as c:
            c.execute(
                """
                INSERT OR IGNORE INTO findings
                  (scan_id, site, finding_kind, component_type, component_name,
                   component_version, title, severity, cvss, fixed_in, cves, refs, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    scan_id, site, f.get("finding_kind"), f.get("component_type"),
                    f.get("component_name"), f.get("component_version"), f.get("title"),
                    f.get("severity"), f.get("cvss"), f.get("fixed_in"),
                    json.dumps(f.get("cves") or []),
                    json.dumps(f.get("references") or []),
                    time.time(),
                ),
            )

    def all_findings(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM findings").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["cves"] = json.loads(d.pop("cves") or "[]")
            d["references"] = json.loads(d.pop("refs") or "[]")
            out.append(d)
        return out

    def clear(self) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM findings")
            c.execute("DELETE FROM scans")
