from __future__ import annotations

import base64
import os
import secrets
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_AESGCM = True
except ImportError:
    HAS_AESGCM = False


class VaultCrypto:
    """
    AES-256-GCM authenticated encryption for sensitive security telemetry,
    forensic records, and audit log payloads.
    Provides confidentiality, integrity, and authenticity guarantees.
    """

    KEY_SIZE_BYTES = 32  # 256-bit AES
    NONCE_SIZE_BYTES = 12  # Standard 96-bit GCM nonce

    def __init__(self, key: Optional[bytes] = None) -> None:
        if not HAS_AESGCM:
            raise RuntimeError("cryptography library required for AES-256-GCM encryption.")
        self.key = key or self.generate_key()
        self._cipher = AESGCM(self.key)

    @classmethod
    def generate_key(cls) -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @classmethod
    def key_to_hex(cls, key: bytes) -> str:
        return key.hex()

    @classmethod
    def key_from_hex(cls, hex_str: str) -> bytes:
        return bytes.fromhex(hex_str.strip())

    def encrypt(self, plaintext: str | bytes, associated_data: Optional[bytes] = None) -> str:
        data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
        nonce = secrets.token_bytes(self.NONCE_SIZE_BYTES)
        # AES-GCM appends the 16-byte authentication tag to the ciphertext
        ciphertext_and_tag = self._cipher.encrypt(nonce, data, associated_data)
        # Store as: base64(nonce + ciphertext_and_tag)
        combined = nonce + ciphertext_and_tag
        return base64.b64encode(combined).decode("ascii")

    def decrypt(self, encoded_payload: str, associated_data: Optional[bytes] = None) -> str:
        combined = base64.b64decode(encoded_payload.encode("ascii"))
        if len(combined) < self.NONCE_SIZE_BYTES + 16:
            raise ValueError("Ciphertext payload is truncated or invalid.")

        nonce = combined[: self.NONCE_SIZE_BYTES]
        ciphertext_and_tag = combined[self.NONCE_SIZE_BYTES :]
        plaintext_bytes = self._cipher.decrypt(nonce, ciphertext_and_tag, associated_data)
        return plaintext_bytes.decode("utf-8")
