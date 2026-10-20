from __future__ import annotations

import json
import tempfile
from pathlib import Path
from blackice.api.router import ApiRouter
from blackice.core.database import ThreatDatabase
from blackice.core.scoring import ThreatScorer
from blackice.core.trie import RadixTrie
from blackice.firewall.mock import MockDriver


def test_api_router_endpoints() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db = ThreatDatabase(Path(tmpdir) / "test.db")
        try:
            trie = RadixTrie()
            scorer = ThreatScorer()
            firewall = MockDriver()
            firewall.initialize()

            events = []
            router = ApiRouter(
                db=db,
                trie=trie,
                scorer=scorer,
                firewall=firewall,
                driver_name="mock",
                event_broadcaster=lambda ev: events.append(ev),
            )

            # Health
            code, ctype, body = router.handle_get("/health")
            assert code == 200
            assert json.loads(body)["status"] == "ok"

            # Cockpit HTML
            code, ctype, body = router.handle_get("/cockpit")
            assert code == 200
            assert "text/html" in ctype
            assert b"BLACKICE" in body

            # Clean IP query
            code, ctype, body = router.handle_get("/v1/intel/1.1.1.1")
            assert code == 200
            res = json.loads(body)
            assert res["threat_score"] == 0
            assert res["action"] == "PASS"
            assert "consensus" in res
            assert res["consensus"]["ratio"] == "0/4"

            # Multi-Engine Consensus Inspector (Decoy Trap probe)
            code, ctype, body = router.handle_post(
                "/v1/consensus/inspect",
                json.dumps({"ip": "100.64.0.1", "path": "/.env", "auto_ban": True}).encode("utf-8"),
            )
            assert code == 200
            c_res = json.loads(body)
            assert c_res["verdict"] == "MALICIOUS"
            assert c_res["action"] == "DROP"
            assert c_res["auto_banned"] is True
            assert firewall.is_banned("100.64.0.1")

            # Shannon Entropy & Exploit Payload Inspector
            code, ctype, body = router.handle_post(
                "/v1/payload/inspect",
                json.dumps({"payload": "admin' OR 1=1--"}).encode("utf-8"),
            )
            assert code == 200
            p_res = json.loads(body)
            assert p_res["is_suspicious"] is True
            assert "sqli_tautology" in p_res["suspicious_patterns"]

            # Canary Traps list
            code, ctype, body = router.handle_get("/v1/canary/traps")
            assert code == 200
            traps_data = json.loads(body)
            assert "/.env" in traps_data["traps"]

            # Ban IP via POST
            ban_payload = json.dumps({"ip": "203.0.113.5", "reason": "Hostile brute force", "ttl_seconds": 3600}).encode("utf-8")
            code, ctype, body = router.handle_post("/v1/firewall/ban", ban_payload)
            assert code == 200
            assert json.loads(body)["banned"] is True
            assert firewall.is_banned("203.0.113.5")

            # Stats
            code, ctype, body = router.handle_get("/v1/stats")
            assert code == 200
            stats = json.loads(body)
            assert stats["driver"] == "mock"
            assert stats["active_bans"] >= 1
            assert "canary_traps_active" in stats

            # Audit Export
            code, ctype, body = router.handle_get("/v1/audit/export")
            assert code == 200
            audit = json.loads(body)
            assert "sha256_hash" in audit
            assert audit["system"].startswith("BLACKICE")

            # Unban IP
            unban_payload = json.dumps({"ip": "203.0.113.5"}).encode("utf-8")
            code, ctype, body = router.handle_post("/v1/firewall/unban", unban_payload)
            assert code == 200
            assert not firewall.is_banned("203.0.113.5")
        finally:
            db.close()
