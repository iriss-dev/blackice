from __future__ import annotations

import time
from typing import Dict, List, Optional
from blackice.firewall.driver import FirewallDriver


class MockDriver(FirewallDriver):
    """
    In-memory simulated firewall controller for development, CI, macOS, and Windows.
    Tracks active drops, simulated dropped packet counts, and TTLs without kernel privileges.
    """

    def __init__(self) -> None:
        self.bans: Dict[str, Dict[str, Any]] = {}
        self.total_dropped_packets: int = 0
        self.initialized: bool = False

    def initialize(self) -> bool:
        self.initialized = True
        return True

    def ban(self, ip: str, ttl_seconds: int = 86400, comment: str = "") -> bool:
        now = time.time()
        self.bans[ip] = {
            "ip": ip,
            "created_at": now,
            "expires_at": now + ttl_seconds,
            "comment": comment,
            "packets_dropped": 0,
        }
        return True

    def unban(self, ip: str) -> bool:
        if ip in self.bans:
            del self.bans[ip]
            return True
        return False

    def is_banned(self, ip: str) -> bool:
        now = time.time()
        info = self.bans.get(ip)
        if not info:
            return False
        if info["expires_at"] <= now:
            del self.bans[ip]
            return False
        return True

    def simulate_packet_drop(self, ip: str, count: int = 1) -> None:
        if ip in self.bans:
            self.bans[ip]["packets_dropped"] += count
        self.total_dropped_packets += count

    def get_stats(self) -> Dict[str, int]:
        now = time.time()
        # Clean expired
        expired = [ip for ip, d in self.bans.items() if d["expires_at"] <= now]
        for ip in expired:
            del self.bans[ip]

        active_count = len(self.bans)
        dropped_sum = sum(d["packets_dropped"] for d in self.bans.values()) + self.total_dropped_packets
        return {
            "active_rules": active_count,
            "packets_dropped": dropped_sum,
        }

    def teardown(self) -> None:
        self.bans.clear()
        self.initialized = False
