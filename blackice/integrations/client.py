from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, Optional


class BlackIceClient:
    """
    Python client for querying local or remote BlackICE threat sentinels.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8787", timeout: float = 1.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check(self, ip: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/intel/{ip.strip()}"
        req = urllib.request.Request(url, headers={"User-Agent": "blackice-python-sdk"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {
                "ip": ip,
                "threat_score": 0,
                "classification": "OFFLINE_PASS",
                "action": "PASS",
                "daemon_error": str(e),
            }

    def ban(self, ip: str, reason: str = "Client ban", ttl_seconds: int = 86400) -> bool:
        url = f"{self.base_url}/v1/firewall/ban"
        payload = json.dumps({"ip": ip, "reason": reason, "ttl_seconds": ttl_seconds}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def unban(self, ip: str) -> bool:
        url = f"{self.base_url}/v1/firewall/unban"
        payload = json.dumps({"ip": ip}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_stats(self) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/stats"
        req = urllib.request.Request(url, headers={"User-Agent": "blackice-python-sdk"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"error": str(e)}
