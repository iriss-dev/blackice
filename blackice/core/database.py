from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ThreatDatabase:
    """
    SQLite WAL storage for threat intelligence feeds, active bans, and
    tamper-evident hash-chained audit trails.
    """

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=30.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA temp_store = MEMORY;")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cidr TEXT NOT NULL,
                        ip_version INTEGER NOT NULL,
                        feed_source TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        description TEXT,
                        first_seen REAL NOT NULL,
                        last_seen REAL NOT NULL,
                        active INTEGER NOT NULL DEFAULT 1,
                        UNIQUE(cidr, feed_source)
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_cidr ON threat_records(cidr);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_feed ON threat_records(feed_source);")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS firewall_bans (
                        ip TEXT PRIMARY KEY,
                        reason TEXT NOT NULL,
                        threat_score INTEGER NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active',
                        packets_dropped INTEGER NOT NULL DEFAULT 0
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_bans_status ON firewall_bans(status, expires_at);")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS feed_metadata (
                        feed_id TEXT PRIMARY KEY,
                        etag TEXT,
                        last_modified TEXT,
                        record_count INTEGER NOT NULL DEFAULT 0,
                        last_sync_status TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """
                )

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_trail (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        event_type TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        hash TEXT NOT NULL
                    );
                    """
                )

    def upsert_threat_batch(self, feed_source: str, records: List[Dict[str, Any]]) -> int:
        if not records:
            return 0
        now = time.time()
        inserted_or_updated = 0

        with self._lock:
            conn = self._get_conn()
            with conn:
                # Mark previous feed records as inactive before sync
                conn.execute(
                    "UPDATE threat_records SET active = 0 WHERE feed_source = ?",
                    (feed_source,),
                )

                cursor = conn.cursor()
                for r in records:
                    cursor.execute(
                        """
                        INSERT INTO threat_records (
                            cidr, ip_version, feed_source, threat_type, description,
                            first_seen, last_seen, active
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                        ON CONFLICT(cidr, feed_source) DO UPDATE SET
                            threat_type = excluded.threat_type,
                            description = excluded.description,
                            last_seen = excluded.last_seen,
                            active = 1;
                        """,
                        (
                            r["cidr"],
                            r.get("ip_version", 4),
                            feed_source,
                            r.get("threat_type", "unknown"),
                            r.get("description", ""),
                            now,
                            now,
                        ),
                    )
                inserted_or_updated = len(records)

                # Clean up inactive records older than 7 days
                seven_days_ago = now - (7 * 86400)
                conn.execute(
                    "DELETE FROM threat_records WHERE active = 0 AND last_seen < ?",
                    (seven_days_ago,),
                )

        return inserted_or_updated

    def load_all_active_threats(self) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        cursor = conn.execute(
            """
            SELECT cidr, ip_version, feed_source, threat_type, description, last_seen
            FROM threat_records
            WHERE active = 1;
            """
        )
        return [
            {
                "cidr": row["cidr"],
                "ip_version": row["ip_version"],
                "feed": row["feed_source"],
                "threat_type": row["threat_type"],
                "description": row["description"],
                "last_seen": row["last_seen"],
            }
            for row in cursor.fetchall()
        ]

    def set_feed_meta(
        self,
        feed_id: str,
        status: str,
        record_count: int,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ) -> None:
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            with conn:
                conn.execute(
                    """
                    INSERT INTO feed_metadata (
                        feed_id, etag, last_modified, record_count, last_sync_status, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(feed_id) DO UPDATE SET
                        etag = COALESCE(excluded.etag, feed_metadata.etag),
                        last_modified = COALESCE(excluded.last_modified, feed_metadata.last_modified),
                        record_count = excluded.record_count,
                        last_sync_status = excluded.last_sync_status,
                        updated_at = excluded.updated_at;
                    """,
                    (feed_id, etag, last_modified, record_count, status, now),
                )

    def get_feed_meta(self, feed_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM feed_metadata WHERE feed_id = ?",
            (feed_id,),
        ).fetchone()
        if not row:
            return None
        return dict(row)

    def add_ban(self, ip: str, reason: str, threat_score: int, ttl_seconds: int = 86400) -> bool:
        now = time.time()
        expires_at = now + ttl_seconds
        with self._lock:
            conn = self._get_conn()
            with conn:
                conn.execute(
                    """
                    INSERT INTO firewall_bans (
                        ip, reason, threat_score, created_at, expires_at, status
                    ) VALUES (?, ?, ?, ?, ?, 'active')
                    ON CONFLICT(ip) DO UPDATE SET
                        reason = excluded.reason,
                        threat_score = excluded.threat_score,
                        expires_at = excluded.expires_at,
                        status = 'active';
                    """,
                    (ip, reason, threat_score, now, expires_at),
                )
        self.append_audit_event("BAN_ADDED", ip, {"reason": reason, "threat_score": threat_score, "ttl": ttl_seconds})
        return True

    def remove_ban(self, ip: str, reason: str = "manual_unban") -> bool:
        with self._lock:
            conn = self._get_conn()
            with conn:
                cursor = conn.execute(
                    "UPDATE firewall_bans SET status = 'unbanned' WHERE ip = ? AND status = 'active';",
                    (ip,),
                )
                affected = cursor.rowcount > 0
        if affected:
            self.append_audit_event("BAN_REMOVED", ip, {"reason": reason})
        return affected

    def get_active_bans(self) -> List[Dict[str, Any]]:
        now = time.time()
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT ip, reason, threat_score, created_at, expires_at, packets_dropped
            FROM firewall_bans
            WHERE status = 'active' AND expires_at > ?
            ORDER BY created_at DESC;
            """,
            (now,),
        ).fetchall()
        return [dict(r) for r in rows]

    def increment_drop_count(self, ip: str, count: int = 1) -> None:
        with self._lock:
            conn = self._get_conn()
            with conn:
                conn.execute(
                    "UPDATE firewall_bans SET packets_dropped = packets_dropped + ? WHERE ip = ?;",
                    (count, ip),
                )

    def prune_expired_bans(self) -> List[str]:
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            with conn:
                rows = conn.execute(
                    "SELECT ip FROM firewall_bans WHERE status = 'active' AND expires_at <= ?;",
                    (now,),
                ).fetchall()
                expired_ips = [r["ip"] for r in rows]
                if expired_ips:
                    conn.execute(
                        "UPDATE firewall_bans SET status = 'expired' WHERE status = 'active' AND expires_at <= ?;",
                        (now,),
                    )
        for ip in expired_ips:
            self.append_audit_event("BAN_EXPIRED", ip, {})
        return expired_ips

    def append_audit_event(self, event_type: str, ip: str, details: Dict[str, Any]) -> str:
        now = time.time()
        details_json = json.dumps(details, sort_keys=True)

        with self._lock:
            conn = self._get_conn()
            with conn:
                last_row = conn.execute(
                    "SELECT hash FROM audit_trail ORDER BY id DESC LIMIT 1;"
                ).fetchone()
                prev_hash = last_row["hash"] if last_row else "0" * 64

                hasher = hashlib.sha256()
                hasher.update(prev_hash.encode("utf-8"))
                hasher.update(f"{now:.6f}".encode("utf-8"))
                hasher.update(event_type.encode("utf-8"))
                hasher.update(ip.encode("utf-8"))
                hasher.update(details_json.encode("utf-8"))
                current_hash = hasher.hexdigest()

                conn.execute(
                    """
                    INSERT INTO audit_trail (
                        timestamp, event_type, ip, details_json, prev_hash, hash
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (now, event_type, ip, details_json, prev_hash, current_hash),
                )
        return current_hash

    def get_audit_trail(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT id, timestamp, event_type, ip, details_json, prev_hash, hash
            FROM audit_trail
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d.pop("details_json"))
            except Exception:
                d["details"] = {}
            results.append(d)
        return results

    def get_stats(self) -> Dict[str, Any]:
        now = time.time()
        conn = self._get_conn()
        threat_count = conn.execute(
            "SELECT COUNT(*) as count FROM threat_records WHERE active = 1;"
        ).fetchone()["count"]

        ban_stats = conn.execute(
            """
            SELECT 
                COUNT(*) as active_bans,
                COALESCE(SUM(packets_dropped), 0) as total_dropped
            FROM firewall_bans
            WHERE status = 'active' AND expires_at > ?;
            """,
            (now,),
        ).fetchone()

        feed_rows = conn.execute("SELECT * FROM feed_metadata;").fetchall()
        feeds = {r["feed_id"]: dict(r) for r in feed_rows}

        return {
            "indexed_threats": threat_count,
            "active_bans": ban_stats["active_bans"],
            "total_packets_dropped": ban_stats["total_dropped"],
            "feed_status": feeds,
        }

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None
