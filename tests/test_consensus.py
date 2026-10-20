import json
import pytest
from blackice.core.canary import CanaryDecoyEngine
from blackice.core.consensus import ConsensusEngine, HeuristicClientInspector
from blackice.core.entropy import ShannonEntropyAnalyzer
from blackice.core.scoring import ThreatScorer
from blackice.core.trie import RadixTrie


@pytest.fixture
def test_system():
    trie = RadixTrie()
    trie.insert("185.220.101.5/32", {"feed": "tor_exits", "description": "Tor exit node", "threat_type": "tor_exit"})
    trie.insert("198.51.100.0/24", {"feed": "feodo_tracker", "description": "Feodo C2 host", "threat_type": "botnet_c2"})

    scorer = ThreatScorer()
    canary = CanaryDecoyEngine()
    entropy = ShannonEntropyAnalyzer()
    consensus = ConsensusEngine(trie, scorer, canary, entropy)
    return consensus


def test_clean_traffic(test_system):
    res = test_system.evaluate(ip="8.8.8.8", path="/", user_agent="Mozilla/5.0")
    assert res.flagged_engines == 0
    assert res.ratio == "0/4"
    assert res.verdict == "CLEAN"
    assert res.action == "PASS"
    assert res.confidence >= 0.95


def test_canary_honeytrap_dropped(test_system):
    res = test_system.evaluate(ip="100.64.0.5", path="/.env", user_agent="curl/7.88")
    assert res.verdict == "MALICIOUS"
    assert res.action == "DROP"
    assert res.confidence == 1.0
    assert res.threat_score == 100
    assert res.engines["canary_decoy"].flagged is True


def test_tor_exit_with_scanner_toolkit(test_system):
    # Both Feeds (Tor) and Client Heuristics (Masscan) flag
    res = test_system.evaluate(ip="185.220.101.5", path="/", user_agent="masscan/1.3")
    assert res.flagged_engines >= 2
    assert res.verdict == "MALICIOUS"
    assert res.action == "DROP"
    assert res.threat_score >= 80


def test_exploit_payload_quarantine(test_system):
    res = test_system.evaluate(
        ip="8.8.4.4",
        path="/search",
        payload="1' UNION SELECT NULL, password FROM users--",
        user_agent="Mozilla/5.0",
    )
    assert res.engines["payload_entropy"].flagged is True
    assert res.action in ("QUARANTINE", "DROP")
    assert res.threat_score >= 80


def test_scanner_toolkit_detection():
    res = HeuristicClientInspector.evaluate_client("sqlmap/1.5#stable")
    assert res.flagged is True
    assert res.score >= 90
    assert res.category == "SCANNER_TOOLKIT"
