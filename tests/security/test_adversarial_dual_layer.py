"""Dual-layer adversarial tests — both shares required for plaintext."""

from __future__ import annotations

import pytest

from core.crypto.python.kdf_aead import (
    DOMAIN_ATTR,
    DOMAIN_ROLE,
    PAYLOAD_VERSION,
    PayloadBlob,
    aead_decrypt,
    aead_encrypt,
    derive_segment_key,
    kdf_gt,
)
from tests.security._helpers import (
    clone_seg,
    default_tree,
    provision,
    setup_crypto,
)


def test_attribute_authorized_role_unauthorized():
    c = setup_crypto()
    # Satisfies AND(doctor,cardiology) but Nurse ≱ AttendingPhysician
    ak, rk, roles = provision(c, "u", ["doctor", "cardiology"], ["Nurse"])
    tree = default_tree()
    seg = c.protect_segment(b"need-role", tree, ["AttendingPhysician"])
    with pytest.raises(PermissionError, match="role"):
        c.recover_segment(seg, ak, rk, roles)


def test_role_authorized_attribute_unauthorized():
    c = setup_crypto()
    ak, rk, roles = provision(c, "u", ["nurse"], ["AttendingPhysician"])
    tree = default_tree()
    seg = c.protect_segment(b"need-attr", tree, ["AttendingPhysician"])
    with pytest.raises(PermissionError, match="attribute"):
        c.recover_segment(seg, ak, rk, roles)


def test_one_z_share_corrupted_fails_aead():
    c = setup_crypto()
    ak, rk, roles = provision(c, "u", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = default_tree()
    pt = b"dual"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    # Corrupt ZA share in keying
    bad_za = c.sample_ZA()
    bad_key = derive_segment_key(bad_za, seg.ZR)
    with pytest.raises(Exception):
        aead_decrypt(bad_key, seg.ct_aes)
    bad_zr = c.sample_ZR()
    bad_key2 = derive_segment_key(seg.ZA, bad_zr)
    with pytest.raises(Exception):
        aead_decrypt(bad_key2, seg.ct_aes)
    assert c.recover_segment(seg, ak, rk, roles) == pt


def test_wrong_kdf_branch_fails():
    c = setup_crypto()
    ak, rk, roles = provision(c, "u", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = default_tree()
    pt = b"kdf"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    # Swap domain labels (wrong KDF branch)
    ka = kdf_gt(seg.ZA, DOMAIN_ROLE)  # should be ATTR
    kr = kdf_gt(seg.ZR, DOMAIN_ATTR)  # should be ROLE
    wrong = bytes(a ^ b for a, b in zip(ka, kr))
    with pytest.raises(Exception):
        aead_decrypt(wrong, seg.ct_aes)
    # Same domain twice
    both_attr = bytes(a ^ b for a, b in zip(kdf_gt(seg.ZA, DOMAIN_ATTR), kdf_gt(seg.ZR, DOMAIN_ATTR)))
    with pytest.raises(Exception):
        aead_decrypt(both_attr, seg.ct_aes)
    assert derive_segment_key(seg.ZA, seg.ZR) == seg.key
    assert c.recover_segment(seg, ak, rk, roles) == pt


def test_wrong_metadata_version_fails():
    c = setup_crypto()
    ak, rk, roles = provision(c, "u", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = default_tree()
    pt = b"ver"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    blob = PayloadBlob.decode(seg.ct_aes)
    bad = PayloadBlob(
        version=(PAYLOAD_VERSION + 1) & 0xFF,
        alg_id=blob.alg_id,
        nonce=blob.nonce,
        ciphertext_and_tag=blob.ciphertext_and_tag,
    ).encode()
    with pytest.raises(ValueError, match="unsupported payload"):
        aead_decrypt(seg.key, bad)
    # Wrong alg id
    bad2 = PayloadBlob(
        version=blob.version,
        alg_id=(blob.alg_id + 1) & 0xFF,
        nonce=blob.nonce,
        ciphertext_and_tag=blob.ciphertext_and_tag,
    ).encode()
    with pytest.raises(ValueError, match="unsupported payload"):
        aead_decrypt(seg.key, bad2)
    assert c.recover_segment(seg, ak, rk, roles) == pt


def test_payload_tampering_fails():
    c = setup_crypto()
    ak, rk, roles = provision(c, "u", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = default_tree()
    pt = b"payload-tamper"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    bad = clone_seg(seg)
    raw = bytearray(bad.ct_aes)
    raw[-1] ^= 0xFF
    bad.ct_aes = bytes(raw)
    with pytest.raises(Exception):
        c.recover_segment(bad, ak, rk, roles)
    # Flip nonce region
    bad2 = clone_seg(seg)
    raw2 = bytearray(bad2.ct_aes)
    raw2[5] ^= 0x01
    bad2.ct_aes = bytes(raw2)
    with pytest.raises(Exception):
        c.recover_segment(bad2, ak, rk, roles)
