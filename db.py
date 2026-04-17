"""
SQLite-backed scan history storage for NetProbe.
Uses only stdlib sqlite3 — no external dependencies.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

_DB_PATH = os.environ.get(
    "NETPROBE_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "netprobe.db"),
)

_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(_DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they don't exist."""
    with _lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                created_at TEXT NOT NULL,
                grade TEXT,
                score INTEGER,
                issues_count INTEGER DEFAULT 0,
                data TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)"
        )


def _summarize(results):
    """Extract grade, score and issue count from scan results."""
    grade = None
    score = None
    issues = 0

    tls = results.get("tls_deep") or {}
    if tls.get("success"):
        grade = tls.get("grade")
        issues += len(tls.get("warnings") or [])

    headers = results.get("http_headers") or {}
    if headers.get("success"):
        score = headers.get("score")
        issues += len(headers.get("headers_missing") or [])

    for key in ("spf", "dmarc", "dkim", "mta_sts", "tlsrpt"):
        block = results.get(key) or {}
        if block and not block.get("pass", True):
            issues += 1

    if (results.get("https_redirect") or {}).get("pass") is False:
        issues += 1

    dnssec = results.get("dnssec") or {}
    if dnssec and not dnssec.get("signed"):
        issues += 1

    bl = results.get("blacklist") or {}
    if bl.get("is_listed"):
        issues += len(bl.get("listed") or [])

    return grade, score, issues


def save_scan(domain, results):
    """Persist a scan result, return the new row id."""
    grade, score, issues = _summarize(results)
    created_at = datetime.now(timezone.utc).isoformat()
    payload = json.dumps(results, default=str)

    with _lock, _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (domain, created_at, grade, score, issues_count, data)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (domain, created_at, grade, score, issues, payload),
        )
        return cur.lastrowid


def list_scans(domain=None, limit=100):
    """Return recent scans, optionally filtered by domain."""
    with _lock, _connect() as conn:
        if domain:
            rows = conn.execute(
                """
                SELECT id, domain, created_at, grade, score, issues_count
                FROM scans WHERE domain = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (domain, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, domain, created_at, grade, score, issues_count
                FROM scans
                ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id):
    """Return a full scan record including the JSON data, or None."""
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        record = dict(row)
        try:
            record["data"] = json.loads(record["data"])
        except (TypeError, ValueError):
            record["data"] = {}
        return record


def delete_scan(scan_id):
    """Remove a single scan. Returns True if a row was deleted."""
    with _lock, _connect() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


def clear_history():
    """Remove every stored scan."""
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM scans")


def history_stats():
    """Return simple aggregate stats for the dashboard."""
    with _lock, _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        domains = conn.execute(
            "SELECT COUNT(DISTINCT domain) AS c FROM scans"
        ).fetchone()["c"]
        last = conn.execute(
            "SELECT created_at FROM scans ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return {
            "total_scans": total,
            "unique_domains": domains,
            "last_scan": last["created_at"] if last else None,
        }
