from __future__ import annotations

import time
from blackice.firewall.mock import MockDriver


def test_mock_driver_lifecycle() -> None:
    driver = MockDriver()
    assert driver.initialize()

    ip = "185.220.101.5"
    assert not driver.is_banned(ip)

    driver.ban(ip, ttl_seconds=2, comment="Test drop")
    assert driver.is_banned(ip)

    driver.simulate_packet_drop(ip, count=15)
    stats = driver.get_stats()
    assert stats["active_rules"] == 1
    assert stats["packets_dropped"] >= 15

    # Test manual unban
    assert driver.unban(ip)
    assert not driver.is_banned(ip)

    # Test TTL expiration
    driver.ban(ip, ttl_seconds=1)
    assert driver.is_banned(ip)
    time.sleep(1.2)
    assert not driver.is_banned(ip)

    driver.teardown()
