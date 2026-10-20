from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import urllib.parse

from blackice.core.database import ThreatDatabase
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
    ) -> None:
        self.db = db
        self.trie = trie
        self.scorer = scorer
        self.firewall = firewall
        self.driver_name = driver_name
        self.broadcast = event_broadcaster
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
            body = json.dumps({"status": "ok", "version": "1.0.0"}).encode("utf-8")
            return 200, "application/json", body

        if clean_path == "/v1/stats":
            stats = self.db.get_stats()
            fw_stats = self.firewall.get_stats()
            stats["driver"] = self.driver_name
            stats["firewall_active_rules"] = fw_stats.get("active_rules", 0)
            stats["firewall_dropped"] = fw_stats.get("packets_dropped", 0)
            body = json.dumps(stats).encode("utf-8")
            return 200, "application/json", body

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
        matches = self.trie.lookup_all(ip_str)
        verdict = self.scorer.evaluate(ip_str, matches)
        is_banned = self.firewall.is_banned(ip_str)

        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except Exception:
            hostname = None

        resp = {
            "ip": verdict.ip,
            "hostname": hostname,
            "threat_score": verdict.threat_score,
            "classification": verdict.classification,
            "action": verdict.action,
            "confidence": verdict.confidence,
            "matched_feeds": verdict.matched_feeds,
            "descriptions": verdict.descriptions,
            "is_malicious": verdict.is_malicious,
            "is_evasion": verdict.is_evasion,
            "is_banned": is_banned,
            "analyzed_at": verdict.analyzed_at,
        }

        # Broadcast live telemetry event
        event_type = "DROP" if verdict.threat_score >= 75 else "INSPECT"
        self.broadcast(
            {
                "timestamp": verdict.analyzed_at,
                "event_type": event_type,
                "ip": verdict.ip,
                "message": f"Score: {verdict.threat_score} ({verdict.classification}) -> {verdict.action}",
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
