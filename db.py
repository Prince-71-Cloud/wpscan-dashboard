"""
db.py
=====
Thin SQLite persistence layer. Single file, single user, no ORM — deliberately
minimal. Tables:

  scans            one row per (site, scan attempt): status + metadata + error,
                   plus the new/fixed counts the scan produced.
  findings         the normalized findings, always reflecting the LATEST
                   successful scan for each site.
  finding_history  one row per distinct finding per site, kept across scans:
                   first_seen / last_seen / resolved_at / status. This is what
                   turns a scan into a diff ("3 new, 2 fixed").
  cve_cache        CVSS / EPSS / KEV data fetched from NVD, FIRST and CISA,
                   keyed by CVE id, shared by every site.
  kv               small key/value store (e.g. the cached KEV catalogue).

Re-scanning a site replaces that site's findings so the dashboard never shows
stale duplicates; the history table is updated in the same transaction.
Schema changes are idempotent (CREATE IF NOT EXISTS + ALTER TABLE guarded by
PRAGMA table_info) because users have existing dashboard.db files.
"""

from __future__ import annotations

import json
import os
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

CREATE TABLE IF NOT EXISTS finding_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    site           TEXT NOT NULL,
    component_type TEXT NOT NULL DEFAULT '',   -- '' instead of NULL so the
    component_name TEXT NOT NULL DEFAULT '',   -- unique index actually dedupes
    title          TEXT NOT NULL DEFAULT '',
    severity       TEXT,
    first_seen     REAL,
    last_seen      REAL,
    resolved_at    REAL,
    status         TEXT                        -- new|recurring|regressed|fixed
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_history_key
    ON finding_history(site, component_type, component_name, title);
CREATE INDEX IF NOT EXISTS idx_history_status ON finding_history(site, status);

CREATE TABLE IF NOT EXISTS cve_cache (
    cve          TEXT PRIMARY KEY,
    cvss         REAL,
    vector       TEXT,
    cvss_version TEXT,
    epss         REAL,
    kev          INTEGER NOT NULL DEFAULT 0,
    description  TEXT,
    fetched_at   REAL
);

CREATE TABLE IF NOT EXISTS kv (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at REAL
);
"""

# (table, column, type) added to databases created before the column existed.
_COLUMN_MIGRATIONS = [
    ("findings", "evidence", "TEXT"),          # json object
    ("findings", "epss", "REAL"),
    ("findings", "kev", "INTEGER"),
    ("findings", "cvss_source", "TEXT"),       # 'wpscan' | 'nvd'
    ("findings", "severity_reason", "TEXT"),
    ("scans", "new_count", "INTEGER"),
    ("scans", "fixed_count", "INTEGER"),
]

_FINDING_COLS = ("scan_id", "site", "finding_kind", "component_type", "component_name",
                 "component_version", "title", "severity", "cvss", "fixed_in", "cves",
                 "refs", "created_at", "evidence", "epss", "kev", "cvss_source",
                 "severity_reason")


def _key(f: dict[str, Any]) -> tuple[str, str, str]:
    """History identity of a finding (NULL-safe)."""
    return (f.get("component_type") or "", f.get("component_name") or "",
            f.get("title") or "")


def _row_values(scan_id: int, site: str, f: dict[str, Any], now: float) -> tuple:
    return (
        scan_id, site, f.get("finding_kind"), f.get("component_type"),
        f.get("component_name"), f.get("component_version"), f.get("title"),
        f.get("severity"), f.get("cvss"), f.get("fixed_in"),
        json.dumps(f.get("cves") or []), json.dumps(f.get("references") or []),
        now,
        json.dumps(f["evidence"]) if f.get("evidence") else None,
        f.get("epss"), 1 if f.get("kev") else 0,
        f.get("cvss_source") or ("wpscan" if f.get("cvss") is not None else None),
        f.get("severity_reason"),
    )


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
        created = not os.path.exists(self.path)
        with self._conn() as c:
            c.executescript(_SCHEMA)
            for table, col, ctype in _COLUMN_MIGRATIONS:
                have = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
                if col not in have:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ctype}")
        if created:
            # The file holds unpatched-vulnerability details about real client
            # sites; keep it from other local accounts.
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

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
    def replace_findings(self, site: str, scan_id: int,
                         findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Store the final finding set for a site and update its history in
        the same transaction. Returns the diff against the previous scan:
        {"new": [titles], "fixed": [titles], "regressed": [titles],
         "recurring": n}."""
        site = site.rstrip("/")
        now = time.time()
        diff: dict[str, Any] = {"new": [], "fixed": [], "regressed": [], "recurring": 0}
        with self._conn() as c:
            c.execute("DELETE FROM findings WHERE site = ?", (site,))
            # OR IGNORE: a report can legitimately repeat a finding (same
            # component + title); keep one instead of failing the whole save.
            c.executemany(
                f"INSERT OR IGNORE INTO findings ({', '.join(_FINDING_COLS)}) "
                f"VALUES ({', '.join('?' * len(_FINDING_COLS))})",
                [_row_values(scan_id, site, f, now) for f in findings],
            )

            # --- history -------------------------------------------------- #
            prev = {(r["component_type"], r["component_name"], r["title"]): dict(r)
                    for r in c.execute("SELECT * FROM finding_history WHERE site = ?",
                                       (site,))}
            present: set[tuple[str, str, str]] = set()
            for f in findings:
                k = _key(f)
                if k in present:
                    continue
                present.add(k)
                old = prev.get(k)
                if old is None:
                    c.execute(
                        "INSERT INTO finding_history (site, component_type, "
                        "component_name, title, severity, first_seen, last_seen, "
                        "resolved_at, status) VALUES (?,?,?,?,?,?,?,NULL,'new')",
                        (site, *k, f.get("severity"), now, now))
                    diff["new"].append(k[2])
                elif old["status"] == "fixed":
                    c.execute(
                        "UPDATE finding_history SET last_seen=?, severity=?, "
                        "resolved_at=NULL, status='regressed' WHERE id=?",
                        (now, f.get("severity"), old["id"]))
                    diff["regressed"].append(k[2])
                else:
                    c.execute(
                        "UPDATE finding_history SET last_seen=?, severity=?, "
                        "status='recurring' WHERE id=?",
                        (now, f.get("severity"), old["id"]))
                    diff["recurring"] += 1
            for k, old in prev.items():
                if k not in present and old["status"] != "fixed":
                    c.execute(
                        "UPDATE finding_history SET resolved_at=?, status='fixed' "
                        "WHERE id=?", (now, old["id"]))
                    diff["fixed"].append(k[2])
        return diff

    def add_finding_live(self, site: str, scan_id: int, f: dict[str, Any]) -> None:
        """Insert a single finding immediately as it's discovered during a live scan.
        Existing findings for the same site are NOT cleared first — replace_findings
        is called at the end of the scan to produce the final clean set. This method
        is purely for making findings appear in the UI table in real time."""
        site = site.rstrip("/")
        with self._conn() as c:
            c.execute(
                f"INSERT OR IGNORE INTO findings ({', '.join(_FINDING_COLS)}) "
                f"VALUES ({', '.join('?' * len(_FINDING_COLS))})",
                _row_values(scan_id, site, f, time.time()),
            )

    def all_findings(self) -> list[dict[str, Any]]:
        """Current findings with their history (first/last seen, new/recurring/
        regressed) attached."""
        with self._conn() as c:
            rows = c.execute(
                """
                SELECT f.*, h.first_seen, h.last_seen, h.status AS history_status
                FROM findings f
                LEFT JOIN finding_history h
                  ON h.site = f.site
                 AND h.component_type = COALESCE(f.component_type, '')
                 AND h.component_name = COALESCE(f.component_name, '')
                 AND h.title = COALESCE(f.title, '')
                """
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["cves"] = json.loads(d.pop("cves") or "[]")
            d["references"] = json.loads(d.pop("refs") or "[]")
            ev = d.pop("evidence", None)
            d["evidence"] = json.loads(ev) if ev else None
            d["kev"] = bool(d.get("kev"))
            out.append(d)
        return out

    def findings_with_cves(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT id, site, title, severity, cvss, cvss_source, cves, epss, kev, "
                "severity_reason FROM findings WHERE cves IS NOT NULL AND cves != '[]'"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["cves"] = json.loads(d["cves"] or "[]")
            out.append(d)
        return out

    def update_finding_fields(self, finding_id: int, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._conn() as c:
            c.execute(f"UPDATE findings SET {cols} WHERE id = ?",
                      (*fields.values(), finding_id))

    # -- history ----------------------------------------------------------- #
    def resolved_findings(self, site: str | None = None, since: float | None = None,
                          limit: int = 200) -> list[dict[str, Any]]:
        """Findings that disappeared from a later scan, newest first."""
        sql = "SELECT * FROM finding_history WHERE status = 'fixed'"
        args: list[Any] = []
        if site:
            sql += " AND site = ?"
            args.append(site.rstrip("/"))
        if since is not None:
            sql += " AND resolved_at >= ?"
            args.append(since)
        sql += " ORDER BY resolved_at DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, args)]

    # -- CVE cache --------------------------------------------------------- #
    def cve_cache_get(self, cves: list[str]) -> dict[str, dict[str, Any]]:
        if not cves:
            return {}
        out: dict[str, dict[str, Any]] = {}
        with self._conn() as c:
            for i in range(0, len(cves), 500):
                chunk = cves[i:i + 500]
                q = ",".join("?" * len(chunk))
                for r in c.execute(f"SELECT * FROM cve_cache WHERE cve IN ({q})", chunk):
                    out[r["cve"]] = dict(r)
        return out

    def cve_cache_put(self, cve: str, **fields: Any) -> None:
        fields.setdefault("fetched_at", time.time())
        cols = ["cve", *fields]
        with self._conn() as c:
            c.execute(
                f"INSERT INTO cve_cache ({', '.join(cols)}) VALUES "
                f"({', '.join('?' * len(cols))}) ON CONFLICT(cve) DO UPDATE SET "
                + ", ".join(f"{k} = excluded.{k}" for k in fields),
                (cve, *fields.values()),
            )

    def kv_get(self, key: str) -> tuple[Any, float] | None:
        with self._conn() as c:
            r = c.execute("SELECT value, updated_at FROM kv WHERE key = ?", (key,)).fetchone()
        if not r:
            return None
        return json.loads(r["value"]), r["updated_at"]

    def kv_set(self, key: str, value: Any) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO kv (key, value, updated_at) VALUES (?,?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                      "updated_at=excluded.updated_at",
                      (key, json.dumps(value), time.time()))

    def clear(self) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM findings")
            c.execute("DELETE FROM scans")
            c.execute("DELETE FROM finding_history")
