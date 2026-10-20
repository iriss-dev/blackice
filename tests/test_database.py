from __future__ import annotations

import tempfile
import time
from pathlib import Path
from blackice.core.database import ThreatDatabase


def test_database_lifecycle_and_wal() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = ThreatDatabase(db_path)

        # Batch upsert
        records = [
            {"cidr": "185.220.101.5/32", "ip_version": 4, "threat_type": "tor_exit", "description": "Tor node"},
            {"cidr": "194.26.29.0/24", "ip_version": 4, "threat_type": "hijacked_netblock", "description": "DROP"},
        ]
        count = db.upsert_threat_batch("test_feed", records)
        assert count == 2

        active = db.load_all_active_threats()
        assert len(active) == 2

        # Bans management
        db.add_ban("1.2.3.4", reason="Port scan", threat_score=85, ttl_seconds=10)
        bans = db.get_active_bans()
        assert len(bans) == 1
        assert bans[0]["ip"] == "1.2.3.4"
        assert bans[0]["threat_score"] == 85

        # Unban
        db.remove_ban("1.2.3.4")
        bans_after = db.get_active_bans()
        assert len(bans_after) == 0

        # Audit trail tamper-evident hash chaining
        h1 = db.append_audit_event("TEST_EVENT_1", "10.0.0.1", {"key": "val1"})
        h2 = db.append_audit_event("TEST_EVENT_2", "10.0.0.2", {"key": "val2"})
        assert len(h1) == 64
        assert len(h2) == 64
        assert h1 != h2

        trail = db.get_audit_trail(limit=5)
        assert len(trail) >= 2
        # Verify prev_hash link
        assert trail[0]["prev_hash"] == trail[1]["hash"]

        db.close()
