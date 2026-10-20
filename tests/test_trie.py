from __future__ import annotations

import time
from blackice.core.trie import RadixTrie


def test_trie_ipv4_exact_and_subnet() -> None:
    trie = RadixTrie()
    trie.insert("192.168.1.0/24", {"feed": "test_net", "threat_type": "scanner"})
    trie.insert("192.168.1.50/32", {"feed": "test_host", "threat_type": "botnet_c2"})

    # Host within subnet
    match = trie.lookup("192.168.1.50")
    assert match is not None
    assert match["feed"] == "test_host"  # LPM should pick the /32

    # Another host in the /24
    match_subnet = trie.lookup("192.168.1.99")
    assert match_subnet is not None
    assert match_subnet["feed"] == "test_net"

    # Host outside subnet
    assert trie.lookup("192.168.2.1") is None
    assert trie.lookup("10.0.0.1") is None


def test_trie_ipv6() -> None:
    trie = RadixTrie()
    trie.insert("2001:db8::/32", {"feed": "ipv6_threat", "threat_type": "scanner"})
    trie.insert("2001:db8:85a3::1/128", {"feed": "ipv6_c2", "threat_type": "botnet_c2"})

    match = trie.lookup("2001:db8:85a3::1")
    assert match is not None
    assert match["feed"] == "ipv6_c2"

    match2 = trie.lookup("2001:db8:1234::beef")
    assert match2 is not None
    assert match2["feed"] == "ipv6_threat"

    assert trie.lookup("2600::1") is None


def test_trie_lookup_all() -> None:
    trie = RadixTrie()
    trie.insert("10.0.0.0/8", {"feed": "feed_broad"})
    trie.insert("10.50.0.0/16", {"feed": "feed_mid"})
    trie.insert("10.50.1.1/32", {"feed": "feed_host"})

    matches = trie.lookup_all("10.50.1.1")
    assert len(matches) == 3
    feeds = [m["feed"] for m in matches]
    assert feeds == ["feed_broad", "feed_mid", "feed_host"]


def test_trie_performance() -> None:
    trie = RadixTrie()
    for i in range(100):
        trie.insert(f"185.{i}.0.0/16", {"feed": f"feed_{i}"})

    start = time.perf_counter()
    iterations = 20_000
    for _ in range(iterations):
        trie.lookup("185.42.12.99")
    elapsed = time.perf_counter() - start

    lookups_per_sec = iterations / elapsed
    assert lookups_per_sec > 50_000, f"Expected >50k lookups/sec, got {lookups_per_sec:.0f}"
