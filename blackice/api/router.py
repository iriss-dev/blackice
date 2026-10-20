from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import urllib.parse

from blackice.core.canary import CanaryDecoyEngine
from blackice.core.consensus import ConsensusEngine
from blackice.core.database import ThreatDatabase
from blackice.core.entropy import ShannonEntropyAnalyzer
from blackice.core.scoring import ThreatScorer
from blackice.core.trie import RadixTrie
from blackice.firewall.driver import FirewallDriver

COCKPIT_HTML_PATH = Path(__file__).resolve().parent.parent / "ui" / "cockpit.html"
SHOWCASE_HTML_PATH = Path(__file__).resolve().parent.parent / "ui" / "showcase.html"


class ApiRouter:
    def __init__(
        self,
        db: ThreatDatabase,
        trie: RadixTrie,
        scorer: ThreatScorer,
        firewall: FirewallDriver,
        driver_name: str,
        event_broadcaster: Callable[[Dict[str, Any]], None],
        canary: Optional[CanaryDecoyEngine] = None,
        consensus: Optional[ConsensusEngine] = None,
        entropy: Optional[ShannonEntropyAnalyzer] = None,
    ) -> None:
        self.db = db
        self.trie = trie
        self.scorer = scorer
        self.firewall = firewall
        self.driver_name = driver_name
        self.broadcast = event_broadcaster

        self.canary = canary or CanaryDecoyEngine()
        self.entropy = entropy or ShannonEntropyAnalyzer()
        self.consensus = consensus or ConsensusEngine(
            trie=self.trie,
            scorer=self.scorer,
            canary=self.canary,
            entropy_analyzer=self.entropy,
        )

        self._cockpit_html = ""
        self._showcase_html = ""
        self._load_cockpit()

    def _load_cockpit(self) -> None:
        if COCKPIT_HTML_PATH.exists():
            self._cockpit_html = COCKPIT_HTML_PATH.read_text(encoding="utf-8")
        else:
            self._cockpit_html = "<h1>BlackICE Cockpit</h1>"

        if SHOWCASE_HTML_PATH.exists():
            self._showcase_html = SHOWCASE_HTML_PATH.read_text(encoding="utf-8")
        else:
            self._showcase_html = self._cockpit_html

    def handle_get(self, path: str) -> tuple[int, str, bytes]:
        parsed = urllib.parse.urlparse(path)
        clean_path = parsed.path.rstrip("/")

        if clean_path in ("", "/cockpit"):
            return 200, "text/html; charset=utf-8", self._cockpit_html.encode("utf-8")

        if clean_path in ("/showcase", "/demo"):
            return 200, "text/html; charset=utf-8", self._showcase_html.encode("utf-8")

        if clean_path == "/health":
            body = json.dumps({"status": "ok", "version": "1.0.0", "consensus_engine": "active"}).encode("utf-8")
            return 200, "application/json", body

        if clean_path == "/v1/stats":
            stats = self.db.get_stats()
            fw_stats = self.firewall.get_stats()
            stats["driver"] = self.driver_name
            stats["firewall_active_rules"] = fw_stats.get("active_rules", 0)
            stats["firewall_dropped"] = fw_stats.get("packets_dropped", 0)
            stats["canary_traps_active"] = len(self.canary.traps)
            stats["canary_triggers_total"] = len(self.canary.triggered_events)
            body = json.dumps(stats).encode("utf-8")
            return 200, "application/json", body

        if clean_path == "/v1/canary/triggers":
            triggers = self.canary.get_recent_triggers(limit=50)
            return 200, "application/json", json.dumps({"triggers": triggers}).encode("utf-8")

        if clean_path == "/v1/canary/traps":
            traps = sorted(list(self.canary.traps))
            return 200, "application/json", json.dumps({"traps": traps}).encode("utf-8")

        if clean_path == "/v1/firewall/bans":
            bans = self.db.get_active_bans()
            body = json.dumps(bans).encode("utf-8")
            return 200, "application/json", body

        if clean_path == "/v1/audit/export":
            import hashlib
            import time
            stats = self.db.get_stats()
            bans = self.db.get_active_bans()
            report_data = {
                "generated_at": time.time(),
                "system": "BLACKICE Sentinel Threat Defense",
                "version": "1.0.0",
                "driver": self.driver_name,
                "stats": stats,
                "active_bans_count": len(bans),
                "active_bans": bans,
                "canary_triggers_count": len(self.canary.triggered_events),
                "canary_triggers": self.canary.get_recent_triggers(limit=100),
            }
            serialized = json.dumps(report_data, sort_keys=True)
            report_data["sha256_hash"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            body = json.dumps(report_data, indent=2).encode("utf-8")
            return 200, "application/json", body

        if clean_path.startswith("/v1/intel/"):
            ip_str = clean_path.replace("/v1/intel/", "")
            return self._handle_intel(ip_str)

        return 404, "application/json", json.dumps({"error": "Endpoint not found"}).encode("utf-8")

    def _handle_intel(self, ip_str: str) -> tuple[int, str, bytes]:
        import socket
        
        # Run full VirusTotal-style Multi-Engine Consensus
        cv = self.consensus.evaluate(ip=ip_str)
        is_banned = self.firewall.is_banned(ip_str)

        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except Exception:
            hostname = None

        # Build engine breakdown
        engines_dict = {}
        for eng_key, eng_obj in cv.engines.items():
            engines_dict[eng_key] = {
                "engine_name": eng_obj.engine_name,
                "flagged": eng_obj.flagged,
                "score": eng_obj.score,
                "category": eng_obj.category,
                "details": eng_obj.details,
            }

        resp = {
            "ip": cv.ip,
            "hostname": hostname,
            "threat_score": cv.threat_score,
            "classification": cv.verdict,
            "action": cv.action,
            "confidence": cv.confidence,
            "matched_feeds": cv.engines["threat_feeds"].details.get("matched_feeds", []),
            "descriptions": cv.engines["threat_feeds"].details.get("descriptions", []),
            "is_malicious": cv.verdict == "MALICIOUS",
            "is_evasion": cv.engines["threat_feeds"].details.get("is_evasion", False),
            "is_banned": is_banned,
            "analyzed_at": cv.analyzed_at,
            "consensus": {
                "ratio": cv.ratio,
                "flagged_engines": cv.flagged_engines,
                "total_engines": cv.total_engines,
                "detection_rate": cv.detection_rate,
                "verdict": cv.verdict,
                "summary": cv.summary,
                "engines": engines_dict,
            },
        }

        # Broadcast live telemetry event
        event_type = "DROP" if cv.threat_score >= 75 else "INSPECT"
        self.broadcast(
            {
                "timestamp": cv.analyzed_at,
                "event_type": event_type,
                "ip": cv.ip,
                "message": f"Consensus: {cv.ratio} engines ({cv.verdict}) -> {cv.action}",
                "details": resp,
            }
        )

        return 200, "application/json", json.dumps(resp).encode("utf-8")

    def handle_post(self, path: str, body_bytes: bytes) -> tuple[int, str, bytes]:
        try:
            payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            return 400, "application/json", json.dumps({"error": "Invalid JSON payload"}).encode("utf-8")

        clean_path = path.rstrip("/")

        # Multi-Engine Consensus Inspection Endpoint (Full Request Analysis)
        if clean_path in ("/v1/consensus/inspect", "/v1/inspect"):
            ip = payload.get("ip", "127.0.0.1")
            req_path = payload.get("path", "/")
            req_payload = payload.get("payload", "")
            user_agent = payload.get("user_agent", "")
            auto_ban = bool(payload.get("auto_ban", False))

            cv = self.consensus.evaluate(
                ip=ip,
                path=req_path,
                payload=req_payload,
                user_agent=user_agent,
            )

            # Auto-ban if requested and malicious (e.g. Canary honeytrap tripped or 2+ engines flagged)
            banned_now = False
            if auto_ban and cv.action == "DROP":
                reason = f"BlackICE Auto-Mitigation: {cv.summary}"
                self.firewall.ban(ip, ttl_seconds=86400, comment=reason)
                self.db.add_ban(ip, reason=reason, threat_score=cv.threat_score, ttl_seconds=86400)
                banned_now = True
                self.broadcast(
                    {
                        "timestamp": __import__("time").time(),
                        "event_type": "BAN",
                        "ip": ip,
                        "message": f"Auto-Banned: {reason}",
                    }
                )

            engines_dict = {
                k: {
                    "engine_name": v.engine_name,
                    "flagged": v.flagged,
                    "score": v.score,
                    "category": v.category,
                    "details": v.details,
                }
                for k, v in cv.engines.items()
            }

            resp = {
                "ip": cv.ip,
                "ratio": cv.ratio,
                "flagged_engines": cv.flagged_engines,
                "total_engines": cv.total_engines,
                "detection_rate": cv.detection_rate,
                "verdict": cv.verdict,
                "action": cv.action,
                "confidence": cv.confidence,
                "threat_score": cv.threat_score,
                "auto_banned": banned_now,
                "summary": cv.summary,
                "analyzed_at": cv.analyzed_at,
                "engines": engines_dict,
            }

            return 200, "application/json", json.dumps(resp).encode("utf-8")

        # Shannon Entropy & Exploit Payload Inspector
        if clean_path == "/v1/payload/inspect":
            text = payload.get("payload", "")
            analysis = self.entropy.analyze(text)
            resp = {
                "length": analysis.length,
                "shannon_entropy": analysis.shannon_entropy,
                "is_suspicious": analysis.is_suspicious,
                "threat_score": analysis.threat_score,
                "suspicious_patterns": analysis.suspicious_patterns,
                "details": analysis.details,
            }
            return 200, "application/json", json.dumps(resp).encode("utf-8")

        # Register Canary Decoy Trap
        if clean_path == "/v1/canary/traps":
            trap = payload.get("trap_path")
            if not trap:
                return 400, "application/json", json.dumps({"error": "Missing 'trap_path' field"}).encode("utf-8")
            self.canary.register_trap(trap)
            return 200, "application/json", json.dumps({"success": True, "registered": trap}).encode("utf-8")

        if clean_path == "/v1/firewall/ban":
            ip = payload.get("ip")
            reason = payload.get("reason", "Operator manual ban")
            ttl = int(payload.get("ttl_seconds", 86400))
            score = int(payload.get("threat_score", 100))

            if not ip:
                return 400, "application/json", json.dumps({"error": "Missing 'ip' field"}).encode("utf-8")

            # Ban in kernel and database
            self.firewall.ban(ip, ttl_seconds=ttl, comment=reason)
            self.db.add_ban(ip, reason=reason, threat_score=score, ttl_seconds=ttl)

            self.broadcast(
                {
                    "timestamp": __import__("time").time(),
                    "event_type": "BAN",
                    "ip": ip,
                    "message": f"IP banned: {reason} (TTL {ttl}s)",
                }
            )

            return 200, "application/json", json.dumps({"success": True, "ip": ip, "banned": True}).encode("utf-8")

        if clean_path == "/v1/firewall/unban":
            ip = payload.get("ip")
            if not ip:
                return 400, "application/json", json.dumps({"error": "Missing 'ip' field"}).encode("utf-8")

            self.firewall.unban(ip)
            self.db.remove_ban(ip, reason="manual_unban")

            self.broadcast(
                {
                    "timestamp": __import__("time").time(),
                    "event_type": "UNBAN",
                    "ip": ip,
                    "message": "IP unbanned by operator",
                }
            )

            return 200, "application/json", json.dumps({"success": True, "ip": ip, "unbanned": True}).encode("utf-8")

        return 404, "application/json", json.dumps({"error": "Endpoint not found"}).encode("utf-8")
