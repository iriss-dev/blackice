from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from blackice.core.canary import CanaryDecoyEngine, CanaryTrigger
from blackice.core.entropy import ShannonEntropyAnalyzer
from blackice.core.scoring import ThreatScorer, ThreatVerdict
from blackice.core.trie import RadixTrie


@dataclass
class EngineResult:
    engine_id: str
    engine_name: str
    flagged: bool
    score: int  # 0 to 100
    category: str
    details: Dict[str, Any]


@dataclass
class ConsensusVerdict:
    ip: str
    flagged_engines: int
    total_engines: int
    ratio: str
    detection_rate: float
    verdict: str  # CLEAN, SUSPICIOUS, MALICIOUS
    action: str  # PASS, MONITOR, QUARANTINE, DROP
    confidence: float  # 0.0 to 1.0
    threat_score: int  # 0 to 100
    engines: Dict[str, EngineResult]
    analyzed_at: float
    summary: str


class HeuristicClientInspector:
    """
    Lightweight client behavior & User-Agent signature inspector.
    Detects aggressive scanners, automated exploit kits, and toolkits.
    """

    KNOWN_SCANNER_PATTERNS = [
        ("masscan", re.compile(r"masscan", re.IGNORECASE)),
        ("sqlmap", re.compile(r"sqlmap", re.IGNORECASE)),
        ("nikto", re.compile(r"nikto", re.IGNORECASE)),
        ("nmap", re.compile(r"nmap", re.IGNORECASE)),
        ("zgrab", re.compile(r"zgrab", re.IGNORECASE)),
        ("shodan", re.compile(r"shodan", re.IGNORECASE)),
        ("nuclei", re.compile(r"nuclei", re.IGNORECASE)),
        ("gobuster", re.compile(r"gobuster", re.IGNORECASE)),
        ("dirbuster", re.compile(r"dirbuster", re.IGNORECASE)),
        ("wpscan", re.compile(r"wpscan", re.IGNORECASE)),
    ]

    @classmethod
    def evaluate_client(cls, user_agent: str, headers: Optional[Dict[str, str]] = None) -> EngineResult:
        if not user_agent:
            return EngineResult(
                engine_id="client_heuristics",
                engine_name="Client Behavioral Heuristics",
                flagged=False,
                score=0,
                category="BENIGN_CLIENT",
                details={"reason": "Standard API query"},
            )

        ua_lower = user_agent.lower()
        for tool_name, pattern in cls.KNOWN_SCANNER_PATTERNS:
            if pattern.search(ua_lower):
                return EngineResult(
                    engine_id="client_heuristics",
                    engine_name="Client Behavioral Heuristics",
                    flagged=True,
                    score=95,
                    category="SCANNER_TOOLKIT",
                    details={"matched_tool": tool_name, "raw_ua": user_agent},
                )

        # Check for typical headless scripting tools probing public interfaces
        if any(tool in ua_lower for tool in ["python-requests", "go-http-client", "aiohttp"]):
            return EngineResult(
                engine_id="client_heuristics",
                engine_name="Client Behavioral Heuristics",
                flagged=False,
                score=25,
                category="SCRIPTED_CLIENT",
                details={"matched_runtime": ua_lower.split("/")[0], "raw_ua": user_agent},
            )

        return EngineResult(
            engine_id="client_heuristics",
            engine_name="Client Behavioral Heuristics",
            flagged=False,
            score=0,
            category="BENIGN_CLIENT",
            details={"raw_ua": user_agent},
        )


class ConsensusEngine:
    """
    VirusTotal-style multi-engine threat consensus scorer.
    Aggregates Sentinel Radix-Trie Feeds, Canary Honeytraps, Shannon Entropy,
    and Client Behavioral Heuristics to deliver high-precision verdicts with near-zero false positives.
    """

    def __init__(
        self,
        trie: RadixTrie,
        scorer: ThreatScorer,
        canary: CanaryDecoyEngine,
        entropy_analyzer: Optional[ShannonEntropyAnalyzer] = None,
    ) -> None:
        self.trie = trie
        self.scorer = scorer
        self.canary = canary
        self.entropy = entropy_analyzer or ShannonEntropyAnalyzer()

    def evaluate(
        self,
        ip: str,
        path: Optional[str] = None,
        payload: Optional[str] = None,
        user_agent: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> ConsensusVerdict:
        now = time.time()
        engines: Dict[str, EngineResult] = {}

        # 1. Engine: Sentinel Feeds Radix-Trie
        feed_matches = self.trie.lookup_all(ip)
        feed_verdict = self.scorer.evaluate(ip, feed_matches)
        feed_flagged = feed_verdict.is_malicious or feed_verdict.threat_score >= 40 or feed_verdict.is_evasion
        engines["threat_feeds"] = EngineResult(
            engine_id="threat_feeds",
            engine_name="Sentinel Radix-Trie Threat Feeds",
            flagged=feed_flagged,
            score=feed_verdict.threat_score,
            category=feed_verdict.classification,
            details={
                "matched_feeds": feed_verdict.matched_feeds,
                "descriptions": feed_verdict.descriptions,
                "is_evasion": feed_verdict.is_evasion,
            },
        )

        # 2. Engine: Canary Honeytrap Decoys (Zero False Positive Tripwire)
        canary_trigger = self.canary.inspect_request(ip, path or "", user_agent or "")
        if canary_trigger:
            engines["canary_decoy"] = EngineResult(
                engine_id="canary_decoy",
                engine_name="Canary Honeytrap Decoy Tripwire",
                flagged=True,
                score=100,
                category="DECOY_HONEYTRAP_TRIPPED",
                details={
                    "trap_path": canary_trigger.trap_path,
                    "confidence": canary_trigger.confidence,
                    "reason": canary_trigger.reason,
                },
            )
        else:
            engines["canary_decoy"] = EngineResult(
                engine_id="canary_decoy",
                engine_name="Canary Honeytrap Decoy Tripwire",
                flagged=False,
                score=0,
                category="NO_TRIPWIRE",
                details={"inspected_path": path or "/"},
            )

        # 3. Engine: Shannon Entropy & Exploit Payload Inspector
        text_to_inspect = (payload or "") + (" " + path if path else "")
        entropy_res = self.entropy.analyze(text_to_inspect)
        engines["payload_entropy"] = EngineResult(
            engine_id="payload_entropy",
            engine_name="Shannon Entropy & Exploit Inspector",
            flagged=entropy_res.is_suspicious,
            score=entropy_res.threat_score,
            category="EXPLOIT_PAYLOAD" if entropy_res.suspicious_patterns else ("HIGH_ENTROPY" if entropy_res.is_suspicious else "CLEAN"),
            details={
                "shannon_entropy": entropy_res.shannon_entropy,
                "suspicious_patterns": entropy_res.suspicious_patterns,
                "length": entropy_res.length,
            },
        )

        # 4. Engine: Client Behavioral Heuristics
        heuristics_res = HeuristicClientInspector.evaluate_client(user_agent or "", headers)
        engines["client_heuristics"] = heuristics_res

        # Consensus Aggregation
        total_engines = len(engines)
        flagged_count = sum(1 for eng in engines.values() if eng.flagged)
        detection_rate = round((flagged_count / total_engines) * 100, 1)

        # Calculate composite consensus score
        max_score = max(eng.score for eng in engines.values())
        avg_flagged_score = sum(eng.score for eng in engines.values() if eng.flagged) / max(1, flagged_count)

        if canary_trigger:
            # Honeytrap is definitive (0% false positives)
            final_threat_score = 100
            verdict_str = "MALICIOUS"
            action_str = "DROP"
            confidence = 1.0
            summary = f"Canary Honeytrap tripped ({canary_trigger.trap_path}). Immediate DROP."
        elif flagged_count >= 2:
            final_threat_score = min(100, int(max_score * 0.7 + avg_flagged_score * 0.3 + 10))
            verdict_str = "MALICIOUS"
            action_str = "DROP"
            confidence = min(0.99, 0.75 + (flagged_count * 0.08))
            summary = f"{flagged_count}/{total_engines} engines flagged threat. High consensus malicious rating."
        elif flagged_count == 1:
            # Single engine flagged
            final_threat_score = max_score
            if max_score >= 90:
                verdict_str = "MALICIOUS"
                action_str = "DROP"
                confidence = 0.85
                summary = f"1/{total_engines} engine flagged critical threat severity ({max_score}/100)."
            elif max_score >= 70:
                verdict_str = "SUSPICIOUS"
                action_str = "QUARANTINE"
                confidence = 0.80
                summary = f"1/{total_engines} engine flagged high threat severity ({max_score}/100)."
            else:
                verdict_str = "SUSPICIOUS"
                action_str = "MONITOR"
                confidence = 0.70
                summary = f"1/{total_engines} engine flagged moderate severity ({max_score}/100)."
        else:
            final_threat_score = 0
            verdict_str = "CLEAN"
            action_str = "PASS"
            confidence = 0.98
            summary = f"0/{total_engines} engines flagged. Traffic verified clean."

        return ConsensusVerdict(
            ip=ip,
            flagged_engines=flagged_count,
            total_engines=total_engines,
            ratio=f"{flagged_count}/{total_engines}",
            detection_rate=detection_rate,
            verdict=verdict_str,
            action=action_str,
            confidence=round(confidence, 2),
            threat_score=final_threat_score,
            engines=engines,
            analyzed_at=now,
            summary=summary,
        )
