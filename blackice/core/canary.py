from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass
class CanaryTrigger:
    ip: str
    trap_path: str
    user_agent: str
    timestamp: float
    confidence: float  # 1.0 = 100% certainty
    severity: str  # CRITICAL, HIGH
    reason: str


class CanaryDecoyEngine:
    """
    Active Deception & Honeytrap Tripwire Engine.
    Operates with near-zero false positives: legitimate users never probe for
    environment files, git repos, or hidden canary tripwire URLs.
    """

    DEFAULT_DECOY_PATHS: Set[str] = {
        "/.env",
        "/.env.production",
        "/.env.local",
        "/.git/HEAD",
        "/.git/config",
        "/.aws/credentials",
        "/wp-admin",
        "/wp-admin/",
        "/wp-login.php",
        "/xmlrpc.php",
        "/actuator/env",
        "/actuator/gateway/routes",
        "/api/v1/debug",
        "/debug/default/view",
        "/phpinfo.php",
        "/phpmyadmin",
        "/solr/admin",
        "/config.json",
        "/.DS_Store",
        "/canary-trap-token",
        "/__blackice_trap__",
    }

    # Regex patterns for scanning attempts
    SUSPICIOUS_PATH_PATTERNS = [
        re.compile(r"^\/\.git(\/.*)?$", re.IGNORECASE),
        re.compile(r"^\/\.env(\..*)?$", re.IGNORECASE),
        re.compile(r"^\/wp-(content|includes|admin|login)", re.IGNORECASE),
        re.compile(r"^\/actuator(\/.*)?$", re.IGNORECASE),
        re.compile(r"phpmyadmin|pma|myadmin", re.IGNORECASE),
        re.compile(r"(\.bak|\.old|\.backup|\.sql|\.tar\.gz|\.zip)$", re.IGNORECASE),
    ]

    def __init__(self, custom_traps: Optional[List[str]] = None, history_limit: int = 200) -> None:
        self.traps: Set[str] = set(self.DEFAULT_DECOY_PATHS)
        if custom_traps:
            for trap in custom_traps:
                self.traps.add(trap.strip().lower())
        self.history_limit = history_limit
        self.triggered_events: List[CanaryTrigger] = []

    def register_trap(self, path: str) -> None:
        """Register a custom decoy or honeytrap path."""
        self.traps.add(path.strip().lower())

    def is_decoy(self, raw_path: str) -> bool:
        """Check if a path matches any registered canary decoy trap."""
        if not raw_path:
            return False
        clean = raw_path.strip().lower().split("?")[0]
        if clean in self.traps:
            return True
        for pattern in self.SUSPICIOUS_PATH_PATTERNS:
            if pattern.search(clean):
                return True
        return False

    def inspect_request(self, ip: str, path: str, user_agent: str = "") -> Optional[CanaryTrigger]:
        """
        Inspects request path against decoy honeytraps.
        Returns a CanaryTrigger if tripped, or None if clean.
        """
        if not self.is_decoy(path):
            return None

        clean_path = path.strip().split("?")[0]
        trigger = CanaryTrigger(
            ip=ip,
            trap_path=clean_path,
            user_agent=user_agent or "Unknown",
            timestamp=time.time(),
            confidence=1.0,  # Zero false positives on honeypot probe
            severity="CRITICAL",
            reason=f"Canary Honeytrap tripped: probe on decoy path '{clean_path}'",
        )

        self.triggered_events.append(trigger)
        if len(self.triggered_events) > self.history_limit:
            self.triggered_events.pop(0)

        return trigger

    def get_recent_triggers(self, limit: int = 50) -> List[Dict[str, any]]:
        """Returns the most recent canary triggers for audit and cockpit monitoring."""
        return [
            {
                "ip": t.ip,
                "trap_path": t.trap_path,
                "user_agent": t.user_agent,
                "timestamp": t.timestamp,
                "confidence": t.confidence,
                "severity": t.severity,
                "reason": t.reason,
            }
            for t in reversed(self.triggered_events[-limit:])
        ]
