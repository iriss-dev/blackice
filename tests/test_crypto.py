from __future__ import annotations

import pytest
from blackice.core.crypto import VaultCrypto


def test_aes_256_gcm_encrypt_decrypt() -> None:
    vault = VaultCrypto()
    secret = "Sensitive Threat Forensic Telemetry: IP 185.220.101.5"
    
    encrypted = vault.encrypt(secret)
    assert encrypted != secret
    assert isinstance(encrypted, str)

    decrypted = vault.decrypt(encrypted)
    assert decrypted == secret


def test_aes_256_gcm_tamper_detection() -> None:
    vault = VaultCrypto()
    secret = "Original forensic payload"
    encrypted = vault.encrypt(secret)

    # Tamper with the ciphertext
    import base64
    raw = bytearray(base64.b64decode(encrypted))
    raw[-2] ^= 0xFF  # Flip a bit in the authentication tag
    tampered = base64.b64encode(raw).decode("ascii")

    with pytest.raises(Exception):
        vault.decrypt(tampered)
