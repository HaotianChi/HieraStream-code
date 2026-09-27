"""PASH-normalized PH-CP-ABE.

Semantic core (prime-order): Setup / KeyGen / PH.Encrypt / matching / full decrypt
as in Zhang et al. IEEE IoT J. 2018 §V-B, with H=h for algebraic correctness.

Primary E10B encryption charges only Table III online ops (Exp=6L+2, ExpT=2).
Composite-order G_p3/G_p4 subgroup samples are omitted on the common Type-A
substrate and are NOT replaced by unused timed prime-order g_pow.

Optional diagnostic charge_subgroup_sampling=True reintroduces unused NormExp
(1+3L) as PASH_SUBGROUP_SAMPLING_UPPER_BOUND_DIAGNOSTIC only.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from experiments.baselines.common.policy.lsss import (
    LSSSPolicy,
    and_reconstruction_coeffs,
    row_dot,
    share_vector,
)
from experiments.baselines.common.util.timing import OpCounter


def _mods():
    if (os.environ.get("HIERASTREAM_CRYPTO_BACKEND") or "").lower() in ("pbc", "native"):
        from core.crypto.python.pbc_field import Zp
        from core.crypto.python.pbc_groups import GElement, GTElement, PairingContext
    else:
        from core.crypto.python.field import Zp
        from core.crypto.python.groups import GElement, GTElement, PairingContext
    return Zp, GElement, GTElement, PairingContext


def _bytes_to_zp(data: bytes):
    Zp, *_ = _mods()
    return Zp.from_int(int.from_bytes(hashlib.sha256(data).digest(), "big"))


def encode_message(payload32: bytes, pairing) -> object:
    if len(payload32) != 32:
        raise ValueError("protected object must be 32 bytes")
    return pairing.gt_pow_gg(_bytes_to_zp(b"PASH-MSG|" + payload32))


def decode_candidate(gt, payload32: bytes, pairing) -> bool:
    return gt == encode_message(payload32, pairing)


@dataclass
class PASHPublicKey:
    g: object
    g_a: object
    Y: object
    H: object


@dataclass
class PASHMasterKey:
    alpha: object
    a: object
    h: object


@dataclass
class PASHSecretKey:
    names: List[str]
    values: Dict[str, object]
    K: object
    K_prime: object
    K_i: Dict[str, object]


@dataclass
class PASHCiphertext:
    policy_rho: List[str]
    C_delta_tilde: object
    C_delta_hat: object
    C_delta_rows: List[object]
    C1_tilde: object
    C1_hat: object
    C1_rows: List[object]
    D1_rows: List[object]
    num_rows: int


@dataclass
class PhaseCounters:
    """Runtime operation counters for one timed phase."""

    pair: int = 0
    exp: int = 0
    exp_t: int = 0
    g_mul: int = 0
    gt_mul: int = 0
    norm_exp: int = 0  # diagnostic-only unused G samples (not primary E10B)

    def as_dict(self) -> Dict[str, int]:
        return {
            "Pair": self.pair,
            "Exp": self.exp,
            "ExpT": self.exp_t,
            "GMul": self.g_mul,
            "GTMul": self.gt_mul,
            "NormExp": self.norm_exp,
        }


@dataclass
class PASHScheme:
    pairing: object
    pk: PASHPublicKey
    mk: PASHMasterKey
    mode: str = "pash-normalized"
    # Primary E10B: False. Diagnostic upper-bound only: True.
    charge_subgroup_sampling: bool = False
    last_encrypt: PhaseCounters = field(default_factory=PhaseCounters)
    last_matching: PhaseCounters = field(default_factory=PhaseCounters)
    last_full_decrypt: PhaseCounters = field(default_factory=PhaseCounters)

    def _norm_sample_g(self, n: int, ctr: PhaseCounters) -> None:
        """Diagnostic only: unused g_pow stand-ins for paper G_p3/G_p4 samples."""
        if not self.charge_subgroup_sampling:
            return
        Zp, *_ = _mods()
        for _ in range(n):
            _ = self.pairing.g_pow(Zp.random())
            ctr.norm_exp += 1

    @classmethod
    def setup(cls, *, charge_subgroup_sampling: bool = False) -> "PASHScheme":
        Zp, _, _, PairingContext = _mods()
        pairing = PairingContext()
        alpha = Zp.random()
        a = Zp.random()
        g = pairing.g
        h = pairing.g_pow(Zp.random())
        # Paper: H = hZ with Z∈G_p4. Semantic: H=h (subgroup omitted).
        H = h
        Y = pairing.gt_pow_gg(alpha)
        g_a = g.pow(a)
        return cls(
            pairing=pairing,
            pk=PASHPublicKey(g=g, g_a=g_a, Y=Y, H=H),
            mk=PASHMasterKey(alpha=alpha, a=a, h=h),
            charge_subgroup_sampling=charge_subgroup_sampling,
            mode=(
                "pash-normalized-diagnostic-subgroup-sampling"
                if charge_subgroup_sampling
                else "pash-normalized"
            ),
        )

    def keygen(self, attrs: Sequence[Tuple[str, object]]) -> PASHSecretKey:
        """KeyGen — outside formal E10B timers. Subgroup R samples omitted."""
        Zp, *_ = _mods()
        attr_list = list(attrs)
        t = Zp.random()
        K = self.pk.g.pow(self.mk.alpha).mul(self.pk.g.pow(self.mk.a * t))
        K_prime = self.pk.g.pow(t)
        K_i: Dict[str, object] = {}
        values: Dict[str, object] = {}
        names: List[str] = []
        for name, val in attr_list:
            base = self.pk.g.pow(val).mul(self.mk.h)
            K_i[name] = base.pow(t)
            values[name] = val
            names.append(name)
        return PASHSecretKey(names=names, values=values, K=K, K_prime=K_prime, K_i=K_i)

    def encrypt(self, message, policy: LSSSPolicy) -> PASHCiphertext:
        Zp, *_ = _mods()
        ctr = PhaseCounters()
        L = policy.num_rows
        n = policy.num_cols
        s = Zp.random()
        s_prime = Zp.random()
        v = share_vector(s, n)
        v_prime = share_vector(s_prime, n)

        # C̃_Δ = Y^{s'}
        C_delta_tilde = self.pk.Y.pow(s_prime)
        ctr.exp_t += 1
        # Ĉ_Δ = g^{s'} Z_Δ → primary: g^{s'}; Z_Δ omitted (optional NormExp diagnostic)
        C_delta_hat = self.pk.g.pow(s_prime)
        ctr.exp += 1
        self._norm_sample_g(1, ctr)  # Z_Δ — primary: no-op

        C_delta_rows: List[object] = []
        C1_rows: List[object] = []
        D1_rows: List[object] = []
        for x in range(L):
            lam_p = row_dot(policy.matrix[x], v_prime)
            t_val = policy.values[x]
            # C_Δ,x = g^{a λ'} (g^{t} H)^{-s'} Z_Δ,x
            left = self.pk.g_a.pow(lam_p)
            ctr.exp += 1
            right_base = self.pk.g.pow(t_val).mul(self.pk.H)
            ctr.exp += 1
            ctr.g_mul += 1
            right = right_base.pow(-s_prime)
            ctr.exp += 1
            row = left.mul(right)
            ctr.g_mul += 1
            self._norm_sample_g(1, ctr)  # Z_Δ,x — primary: no-op
            C_delta_rows.append(row)

            rx = Zp.random()
            lam = row_dot(policy.matrix[x], v)
            # C1,x = g^{a λ} (g^t H)^{-rx} Zc,x ; D1,x = g^{rx} Zd,x
            left1 = self.pk.g_a.pow(lam)
            ctr.exp += 1
            right1 = right_base.pow(-rx)
            ctr.exp += 1
            c1 = left1.mul(right1)
            ctr.g_mul += 1
            d1 = self.pk.g.pow(rx)
            ctr.exp += 1
            self._norm_sample_g(2, ctr)  # Zc,x Zd,x — primary: no-op
            C1_rows.append(c1)
            D1_rows.append(d1)

        # C̃1 = M · Y^s ; Ĉ1 = g^s
        C1_tilde = message.mul(self.pk.Y.pow(s))
        ctr.exp_t += 1
        ctr.gt_mul += 1
        C1_hat = self.pk.g.pow(s)
        ctr.exp += 1

        self.last_encrypt = ctr
        return PASHCiphertext(
            policy_rho=list(policy.rho),
            C_delta_tilde=C_delta_tilde,
            C_delta_hat=C_delta_hat,
            C_delta_rows=C_delta_rows,
            C1_tilde=C1_tilde,
            C1_hat=C1_hat,
            C1_rows=C1_rows,
            D1_rows=D1_rows,
            num_rows=L,
        )

    def matching_test(self, ct: PASHCiphertext, sk: PASHSecretKey, policy: LSSSPolicy):
        """Matching / decryption-test: constant Pair=2 after aggregation."""
        _, GElement, _, _ = _mods()
        ctr = PhaseCounters()
        for name, t_val in zip(policy.rho, policy.values):
            if name not in sk.values or sk.values[name] != t_val:
                self.last_matching = ctr
                return None

        omega = and_reconstruction_coeffs(policy)
        prod_C = GElement.identity()
        prod_K = GElement.identity()
        for i, w in omega.items():
            name = policy.rho[i]
            prod_C = prod_C.mul(ct.C_delta_rows[i].pow(w))
            prod_K = prod_K.mul(sk.K_i[name].pow(w))
            ctr.exp += 2
            ctr.g_mul += 2

        # Paper: C̃_Δ^{-1} = e(∏C^ω, K') · e(Ĉ_Δ, K^{-1}∏K^ω)  → Pair = 2
        lhs = ct.C_delta_tilde.inv()
        rhs1 = self.pairing.pairing(prod_C, sk.K_prime)
        rhs2 = self.pairing.pairing(ct.C_delta_hat, sk.K.inv().mul(prod_K))
        ctr.pair += 2
        ctr.g_mul += 1
        ctr.gt_mul += 1
        self.last_matching = ctr
        if lhs != rhs1.mul(rhs2):
            return None
        return omega

    def full_decrypt(self, ct: PASHCiphertext, sk: PASHSecretKey, omega: Dict[int, object], policy: LSSSPolicy):
        """Decryption phase with Table-III aggregation: Pair = |I|+2.

        Paper eq. expands to per-row pairings; bilinearity yields the Table III
        count ê(Ĉ1,K) / ( ê(∏C1^ω,K') · ∏ ê(D1,Kρ)^ω ).
        """
        _, GElement, GTElement, _ = _mods()
        ctr = PhaseCounters()
        prod_C1 = GElement.identity()
        den_D = GTElement.identity()
        for i, w in omega.items():
            name = policy.rho[i]
            prod_C1 = prod_C1.mul(ct.C1_rows[i].pow(w))
            ctr.exp += 1
            ctr.g_mul += 1
            p_d = self.pairing.pairing(ct.D1_rows[i], sk.K_i[name])
            ctr.pair += 1
            den_D = den_D.mul(p_d.pow(w))
            ctr.exp_t += 1
            ctr.gt_mul += 1
        num = self.pairing.pairing(ct.C1_hat, sk.K)
        ctr.pair += 1
        den_C = self.pairing.pairing(prod_C1, sk.K_prime)
        ctr.pair += 1
        E = num.mul((den_C.mul(den_D)).inv())
        ctr.gt_mul += 2
        out = ct.C1_tilde.mul(E.inv())
        ctr.gt_mul += 1
        self.last_full_decrypt = ctr
        return out

    def decrypt(self, ct: PASHCiphertext, sk: PASHSecretKey, policy: LSSSPolicy):
        omega = self.matching_test(ct, sk, policy)
        if omega is None:
            return None
        return self.full_decrypt(ct, sk, omega, policy)

    def ciphertext_bytes(self, ct: PASHCiphertext) -> int:
        # Deterministic size accounting (prime-order element approx): GT=32, G≈128 for PBC
        g = 128
        gt = 32
        # (A,ρ) omitted; elements: C̃Δ, ĈΔ, L·CΔ,x, C̃1, Ĉ1, L·(C1,x+D1,x)
        return gt + g + ct.num_rows * g + gt + g + ct.num_rows * (2 * g)
