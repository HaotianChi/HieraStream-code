"""Algebraic randomized equivalence."""

from __future__ import annotations

import pytest

from core.crypto.python.access_tree import AND, leaf
from core.crypto.python.field import Zp
from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
from core.crypto.python.segment import (
    OutsourceAttrKeys,
    OutsourcePartialAttrCT,
    SegmentCrypto,
)


def _fresh_crypto():
    c = SegmentCrypto()
    attrs = ["doctor", "cardiology", "nurse"]
    c.ca_setup()
    c.aa_setup(attrs)
    c.role_setup(HEALTHCARE_FIXTURE)
    return c, attrs


@pytest.mark.parametrize("_rep", range(8))
def test_eq27_28_attr_path_recovers_ZA(_rep: int):
    """Recompute Eqs.(27)–(28): outsource B_j + user recover Z^A."""
    c, attrs = _fresh_crypto()
    user = c.aa_keygen("u", attrs)
    tree = AND(leaf("doctor"), leaf("cardiology"))
    ZA = c.sample_ZA()
    partial = c.gateway_partial_attr(ZA)
    ct = c.outsource_policy_encrypt(partial.to_outsource_view(), tree)
    Bj = c.outsource_attr_transform(ct, user.to_outsource_keys())
    assert Bj is not None
    got = c.user_recover_ZA(ct, Bj, user.usk1)
    assert got == ZA


@pytest.mark.parametrize("_rep", range(8))
def test_eq11_dual_share_key(_rep: int):
    from core.crypto.python.kdf_aead import derive_segment_key

    c, _ = _fresh_crypto()
    ZA, ZR = c.sample_ZA(), c.sample_ZR()
    k1 = derive_segment_key(ZA, ZR)
    k2 = derive_segment_key(ZA, ZR)
    assert k1 == k2
    # Changing either share changes the key
    assert derive_segment_key(c.sample_ZA(), ZR) != k1
    assert derive_segment_key(ZA, c.sample_ZR()) != k1


@pytest.mark.parametrize("_rep", range(5))
def test_eq39_attr_refresh_ratio_algebra(_rep: int):
    """E_new = E_old^{t_old/t_new} so e(E_new, g^{t_new}) = e(E_old, g^{t_old})."""
    from core.authorization.secrecy import compute_attr_update_ratio

    c, attrs = _fresh_crypto()
    user = c.aa_keygen("u", attrs)
    a = "doctor"
    t_old = c.secrets.aa.t_a[a]  # type: ignore
    t_new = Zp.random()
    ratio = compute_attr_update_ratio(t_old, t_new)
    e_old = user.E_ua[a]
    e_new = ratio.apply(e_old)
    # Pairing identity: e(E, g^t) = e(g,g)^{β r_u}
    left = c.ctx.pairing(e_old, c.ctx.g_pow(t_old))
    right = c.ctx.pairing(e_new, c.ctx.g_pow(t_new))
    assert left == right


def test_outsource_keys_exclude_usk1():
    c, attrs = _fresh_crypto()
    user = c.aa_keygen("u", attrs)
    view = user.to_outsource_keys()
    assert isinstance(view, OutsourceAttrKeys)
    assert not hasattr(view, "usk1")
    assert not hasattr(view, "_r_u")
    fields = set(view.__dataclass_fields__)  # type: ignore[attr-defined]
    assert fields == {"user_id", "E", "E1", "E_ua"}


def test_partial_outsource_view_excludes_ZA():
    c, _ = _fresh_crypto()
    ZA = c.sample_ZA()
    partial = c.gateway_partial_attr(ZA)
    view = partial.to_outsource_view()
    assert isinstance(view, OutsourcePartialAttrCT)
    assert not hasattr(view, "ZA")
    assert not hasattr(view, "s1")


def test_outsource_service_rejects_needing_usk1():
    from core.actors.outsource.service import OutsourceService

    c, attrs = _fresh_crypto()
    svc = OutsourceService(crypto=c, hierarchy=HEALTHCARE_FIXTURE)
    user = c.aa_keygen("u", attrs)
    tree = AND(leaf("doctor"), leaf("cardiology"))
    ZA = c.sample_ZA()
    ct = c.outsource_policy_encrypt(c.gateway_partial_attr(ZA).to_outsource_view(), tree)
    Bj = svc.attr_transform(ct, user.to_outsource_keys())
    assert Bj is not None
    # Service API type path never requires usk1 field on the view object
    with pytest.raises(AttributeError):
        _ = user.to_outsource_keys().usk1  # type: ignore[attr-defined]
