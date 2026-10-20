from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class FeedSource:
    id: str
    name: str
    url: str
    threat_type: str
    default_confidence: float
    description: str
    format: str  # "cidr_lines", "ip_lines", "csv", "json"


FEED_REGISTRY: Dict[str, FeedSource] = {
    "spamhaus_drop": FeedSource(
        id="spamhaus_drop",
        name="Spamhaus DROP",
        url="https://www.spamhaus.org/drop/drop.txt",
        threat_type="hijacked_netblock",
        default_confidence=0.95,
        description="Spamhaus Don't Route Or Peer: Hijacked or completely criminal netblocks.",
        format="cidr_lines",
    ),
    "spamhaus_edrop": FeedSource(
        id="spamhaus_edrop",
        name="Spamhaus EDROP",
        url="https://www.spamhaus.org/drop/edrop.txt",
        threat_type="hijacked_netblock",
        default_confidence=0.92,
        description="Spamhaus Extended DROP: Sub-allocated hijacked network ranges.",
        format="cidr_lines",
    ),
    "tor_exits": FeedSource(
        id="tor_exits",
        name="Tor Project Bulk Exits",
        url="https://check.torproject.org/torbulkexitlist",
        threat_type="tor_exit",
        default_confidence=0.99,
        description="Official list of active Tor network exit relays.",
        format="ip_lines",
    ),
    "feodo_tracker": FeedSource(
        id="feodo_tracker",
        name="Feodo Tracker Botnet C2",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        threat_type="botnet_c2",
        default_confidence=0.98,
        description="Abuse.ch Feodo Tracker: Active Botnet Command & Control servers (Dridex, Emotet, Qakbot).",
        format="ip_lines",
    ),
    "emerging_threats": FeedSource(
        id="emerging_threats",
        name="Emerging Threats Compromised IPs",
        url="https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        threat_type="active_scanner",
        default_confidence=0.85,
        description="Proofpoint Emerging Threats: Actively hostile scanning and exploiting hosts.",
        format="ip_lines",
    ),
    "urlhaus_recent": FeedSource(
        id="urlhaus_recent",
        name="URLhaus Malware Hosts",
        url="https://urlhaus.abuse.ch/downloads/text_recent/",
        threat_type="malware_distributor",
        default_confidence=0.90,
        description="Abuse.ch URLhaus: Active hosts serving malware payloads in the past 48h.",
        format="ip_lines",
    ),
}

# Embedded seed data for instant out-of-the-box offline operation
OFFLINE_SEED_RECORDS: List[Dict[str, str]] = [
    # Tor exits sample
    {"cidr": "185.220.101.5/32", "threat_type": "tor_exit", "feed": "tor_exits", "description": "Verified Tor Exit Node"},
    {"cidr": "185.220.101.6/32", "threat_type": "tor_exit", "feed": "tor_exits", "description": "Verified Tor Exit Node"},
    {"cidr": "185.220.101.7/32", "threat_type": "tor_exit", "feed": "tor_exits", "description": "Verified Tor Exit Node"},
    {"cidr": "185.220.102.242/32", "threat_type": "tor_exit", "feed": "tor_exits", "description": "Verified Tor Exit Node"},
    {"cidr": "192.42.116.16/32", "threat_type": "tor_exit", "feed": "tor_exits", "description": "Verified Tor Exit Node"},
    # Feodo C2 sample
    {"cidr": "103.151.125.246/32", "threat_type": "botnet_c2", "feed": "feodo_tracker", "description": "Feodo/Qakbot C2 Server"},
    {"cidr": "109.205.213.120/32", "threat_type": "botnet_c2", "feed": "feodo_tracker", "description": "Feodo/Dridex C2 Server"},
    {"cidr": "185.246.221.75/32", "threat_type": "botnet_c2", "feed": "feodo_tracker", "description": "Feodo/Emotet C2 Server"},
    # Spamhaus DROP sample hijacked ranges
    {"cidr": "194.26.29.0/24", "threat_type": "hijacked_netblock", "feed": "spamhaus_drop", "description": "Spamhaus DROP Hijacked AS"},
    {"cidr": "185.143.223.0/24", "threat_type": "hijacked_netblock", "feed": "spamhaus_drop", "description": "Spamhaus DROP Hijacked AS"},
    {"cidr": "45.154.255.0/24", "threat_type": "hijacked_netblock", "feed": "spamhaus_drop", "description": "Spamhaus DROP Hijacked AS"},
    # Malicious scanners
    {"cidr": "198.235.24.0/24", "threat_type": "active_scanner", "feed": "emerging_threats", "description": "Hostile Reconnaissance Netblock"},
    {"cidr": "71.6.232.0/24", "threat_type": "active_scanner", "feed": "emerging_threats", "description": "Hostile Reconnaissance Netblock"},
]
