from __future__ import annotations

from blackice.feeds.parser import parse_feed_content
from blackice.feeds.sources import FEED_REGISTRY


def test_parse_spamhaus_drop_with_comments() -> None:
    source = FEED_REGISTRY["spamhaus_drop"]
    raw_sample = """
; Spamhaus DROP List 2026/10/20
; https://www.spamhaus.org/drop/drop.txt
;
194.26.29.0/24 ; SBL123456
185.143.223.0/24 ; SBL654321
# Some invalid line or header
bad_token_not_an_ip
45.154.255.0/24
    """
    records = parse_feed_content(source, raw_sample)
    assert len(records) == 3
    cidrs = [r["cidr"] for r in records]
    assert "194.26.29.0/24" in cidrs
    assert "185.143.223.0/24" in cidrs
    assert "45.154.255.0/24" in cidrs
    assert records[0]["threat_type"] == "hijacked_netblock"


def test_parse_tor_bulk_exit_list() -> None:
    source = FEED_REGISTRY["tor_exits"]
    raw_sample = """
# This is a list of all Tor exit nodes
185.220.101.5
185.220.101.6
185.220.102.242
"""
    records = parse_feed_content(source, raw_sample)
    assert len(records) == 3
    for r in records:
        assert r["cidr"].endswith("/32")
        assert r["threat_type"] == "tor_exit"


def test_parse_feodo_tracker() -> None:
    source = FEED_REGISTRY["feodo_tracker"]
    raw_sample = """
# Feodo Tracker IP Blocklist
# Last updated: 2026-10-20
103.151.125.246
109.205.213.120
"""
    records = parse_feed_content(source, raw_sample)
    assert len(records) == 2
    assert records[0]["threat_type"] == "botnet_c2"
