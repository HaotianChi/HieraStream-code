"""Domain-separated KDF + versioned AES-256-GCM payload format."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .groups import GTElement

DOMAIN_ATTR = b"HieraStream-Attribute-v1"
DOMAIN_ROLE = b"HieraStream-Role-v1"

# Payload format version for Enc (AES-256-GCM)
PAYLOAD_VERSION = 1
ALG_ID_AES256GCM = 1


def kdf_gt(z: GTElement, info: bytes) -> bytes:
    """HKDF-SHA-256 from canonical G_T bytes with domain separation."""
    ikm = z.to_bytes()
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(ikm)


def derive_segment_key(z_a: GTElement, z_r: GTElement) -> bytes:
    """Eq.(11): K = KDF(Z^A) XOR KDF(Z^R) with fixed-length outputs."""
    ka = kdf_gt(z_a, DOMAIN_ATTR)
    kr = kdf_gt(z_r, DOMAIN_ROLE)
    if len(ka) != len(kr):
        raise RuntimeError("KDF length mismatch")
    return bytes(a ^ b for a, b in zip(ka, kr))


@dataclass(frozen=True)
class PayloadBlob:
    """Explicit AEAD container: version | alg_id | nonce | ct||tag."""

    version: int
    alg_id: int
    nonce: bytes
    ciphertext_and_tag: bytes

    def encode(self) -> bytes:
        if len(self.nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        header = struct.pack(">BB", self.version & 0xFF, self.alg_id & 0xFF)
        return header + self.nonce + self.ciphertext_and_tag

    @staticmethod
    def decode(data: bytes) -> "PayloadBlob":
        if len(data) < 2 + 12 + 16:
            raise ValueError("payload too short")
        version, alg_id = struct.unpack(">BB", data[:2])
        nonce = data[2:14]
        body = data[14:]
        return PayloadBlob(version=version, alg_id=alg_id, nonce=nonce, ciphertext_and_tag=body)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires 32-byte key")
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return PayloadBlob(
        version=PAYLOAD_VERSION,
        alg_id=ALG_ID_AES256GCM,
        nonce=nonce,
        ciphertext_and_tag=ct,
    ).encode()


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    payload = PayloadBlob.decode(blob)
    if payload.version != PAYLOAD_VERSION or payload.alg_id != ALG_ID_AES256GCM:
        raise ValueError("unsupported payload format")
    return AESGCM(key).decrypt(payload.nonce, payload.ciphertext_and_tag, aad)
