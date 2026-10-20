from __future__ import annotations

from blackice.core.scoring import ThreatScorer


def test_clean_ip_evaluation() -> None:
    scorer = ThreatScorer(ban_threshold=75)
    verdict = scorer.evaluate("1.1.1.1", [])
    assert verdict.threat_score == 0
    assert verdict.classification == "CLEAN"
    assert verdict.action == "PASS"
    assert not verdict.is_malicious
    assert not verdict.is_evasion


def test_botnet_c2_critical_threat() -> None:
    scorer = ThreatScorer(ban_threshold=75)
    matches = [
        {"feed": "feodo_tracker", "threat_type": "botnet_c2", "description": "Qakbot C2"},
    ]
    verdict = scorer.evaluate("103.151.125.246", matches)
    assert verdict.threat_score >= 95
    assert verdict.classification == "BOTNET_C2"
    assert verdict.action == "DROP"
    assert verdict.is_malicious


def test_tor_exit_node_evasion() -> None:
    scorer = ThreatScorer(ban_threshold=75)
    matches = [
        {"feed": "tor_exits", "threat_type": "tor_exit", "description": "Tor Exit Relay"},
    ]
    verdict = scorer.evaluate("185.220.101.5", matches)
    assert 40 <= verdict.threat_score <= 60
    assert verdict.classification == "TOR_EXIT"
    assert verdict.is_evasion
    assert not verdict.is_malicious  # Tor alone is evasion, not confirmed malware


def test_multi_feed_correlation_boost() -> None:
    scorer = ThreatScorer(ban_threshold=75)
    single_match = [
        {"feed": "emerging_threats", "threat_type": "active_scanner"},
    ]
    v_single = scorer.evaluate("1.2.3.4", single_match)

    correlated_matches = [
        {"feed": "emerging_threats", "threat_type": "active_scanner"},
        {"feed": "urlhaus_recent", "threat_type": "malware_distributor"},
        {"feed": "spamhaus_drop", "threat_type": "hijacked_netblock"},
    ]
    v_multi = scorer.evaluate("1.2.3.4", correlated_matches)

    assert v_multi.threat_score > v_single.threat_score
    assert v_multi.threat_score == 100
    assert v_multi.confidence > v_single.confidence
