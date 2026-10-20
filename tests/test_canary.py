import pytest
from blackice.core.canary import CanaryDecoyEngine


def test_canary_default_traps():
    canary = CanaryDecoyEngine()
    # Legitimate path
    assert not canary.is_decoy("/api/v1/users")
    assert not canary.is_decoy("/login")
    assert not canary.is_decoy("/assets/logo.png")

    # Honeytrap decoys
    assert canary.is_decoy("/.env")
    assert canary.is_decoy("/.env.production")
    assert canary.is_decoy("/.git/HEAD")
    assert canary.is_decoy("/wp-admin")
    assert canary.is_decoy("/wp-login.php")
    assert canary.is_decoy("/actuator/env")


def test_canary_custom_registration():
    canary = CanaryDecoyEngine()
    custom_trap = "/__secret_admin_backdoor"
    assert not canary.is_decoy(custom_trap)

    canary.register_trap(custom_trap)
    assert canary.is_decoy(custom_trap)


def test_canary_trigger_event():
    canary = CanaryDecoyEngine()
    trigger = canary.inspect_request(
        ip="198.51.100.22",
        path="/.env",
        user_agent="curl/7.68.0",
    )
    assert trigger is not None
    assert trigger.ip == "198.51.100.22"
    assert trigger.trap_path == "/.env"
    assert trigger.confidence == 1.0
    assert trigger.severity == "CRITICAL"

    recent = canary.get_recent_triggers()
    assert len(recent) == 1
    assert recent[0]["ip"] == "198.51.100.22"


def test_canary_clean_request_returns_none():
    canary = CanaryDecoyEngine()
    trigger = canary.inspect_request(
        ip="198.51.100.22",
        path="/api/v1/health",
        user_agent="Mozilla/5.0",
    )
    assert trigger is None
