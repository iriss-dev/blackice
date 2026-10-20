from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ThreatVerdict:
    ip: str
    threat_score: int
    classification: str
    action: str
    confidence: float
    matched_feeds: List[str]
    descriptions: List[str]
    is_malicious: bool
    is_evasion: bool
    analyzed_at: float


class ThreatScorer:
    """
    Multi-factor threat classification and scoring engine.
    Calculates deterministic risk scores (0-100) based on feed provenance,
    overlap correlation, recency, and threat categories.
    """

    SEVERITY_WEIGHTS: Dict[str, int] = {
        "botnet_c2": 95,
        "hijacked_netblock": 90,
        "malware_distributor": 88,
        "active_scanner": 75,
        "compromised_host": 70,
        "tor_exit": 45,
        "vpn_datacenter": 35,
        "unknown": 20,
    }

    def __init__(self, ban_threshold: int = 75) -> None:
        self.ban_threshold = ban_threshold

    def evaluate(self, ip: str, matches: List[Dict[str, Any]]) -> ThreatVerdict:
        now = time.time()
        if not matches:
            return ThreatVerdict(
                ip=ip,
                threat_score=0,
                classification="CLEAN",
                action="PASS",
                confidence=1.0,
                matched_feeds=[],
                descriptions=[],
                is_malicious=False,
                is_evasion=False,
                analyzed_at=now,
            )

        highest_base = 0
        primary_class = "SUSPICIOUS"
        unique_feeds = set()
        descriptions = []
        is_malicious = False
        is_evasion = False

        for match in matches:
            feed = match.get("feed", "unknown")
            unique_feeds.add(feed)
            desc = match.get("description")
            if desc and desc not in descriptions:
                descriptions.append(desc)

            threat_type = match.get("threat_type", "unknown").lower()
            weight = self.SEVERITY_WEIGHTS.get(threat_type, 20)

            if weight > highest_base:
                highest_base = weight
                primary_class = threat_type.upper()

            if weight >= 70:
                is_malicious = True
            if "tor" in threat_type or "vpn" in threat_type:
                is_evasion = True

        # Overlap boost: multi-feed correlation indicates verified threat
        feed_count = len(unique_feeds)
        correlation_bonus = 0
        if feed_count >= 3:
            correlation_bonus = 20
        elif feed_count == 2:
            correlation_bonus = 10

        final_score = min(100, highest_base + correlation_bonus)
        confidence = min(0.99, 0.65 + (feed_count * 0.12))

        if final_score >= self.ban_threshold:
            action = "DROP"
        elif final_score >= 50:
            action = "QUARANTINE"
        elif final_score > 0:
            action = "MONITOR"
        else:
            action = "PASS"

        return ThreatVerdict(
            ip=ip,
            threat_score=final_score,
            classification=primary_class,
            action=action,
            confidence=round(confidence, 2),
            matched_feeds=sorted(list(unique_feeds)),
            descriptions=descriptions,
            is_malicious=is_malicious,
            is_evasion=is_evasion,
            analyzed_at=now,
        )
