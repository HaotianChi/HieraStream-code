"""Simulated bilinear-map backend for HieraStream protocol wiring.

SECURITY NOTICE
---------------
This backend is NOT cryptographically secure. It models the paper's symmetric
bilinear map abstraction as:

    G  ~  additive exponents mod p
    GT ~  multiplicative field elements represented as integers mod p
    e(g^a, g^b) = gT^{a*b}

Formal manuscript experiments MUST use the C++/PBC backend
(core/crypto) once pybind11 bindings are built.

Environment:
    HIERASTREAM_CRYPTO_BACKEND=simulated   (default until PBC bindings load)
    HIERASTREAM_CRYPTO_BACKEND=pbc
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Large safe prime for development simulation only (not a pairing security claim).
_P = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    16,
)  # secp256k1 prime as convenient large prime field


def _rand_zp() -> int:
    while True:
        x = secrets.randbelow(_P - 1) + 1
        if x != 0:
            return x


def _hp(s: str) -> int:
    """H_p : {0,1}* -> Z_p  (manuscript identity hash)."""
    digest = hashlib.sha256(("HieraStream-Hp-v1|" + s).encode("utf-8")).digest()
    return int.from_bytes(digest, "big") % _P


def kdf_gt(z: int, info: bytes) -> bytes:
    """KDF from GT element using HKDF-SHA-256 with domain separation."""
    # Canonical GT serialization: 32-byte big-endian (mod p reduced).
    ikm = (z % _P).to_bytes(32, "big")
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(ikm)


def derive_segment_key(z_a: int, z_r: int) -> bytes:
    # Eq.(11): K = KDF(Z^A) XOR KDF(Z^R)
    ka = kdf_gt(z_a, b"HieraStream-Attribute-v1")
    kr = kdf_gt(z_r, b"HieraStream-Role-v1")
    return bytes(a ^ b for a, b in zip(ka, kr))


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    # Enc must provide confidentiality + integrity (AES-256-GCM).
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)


@dataclass
class AccessTree:
    """Generic threshold access tree (k-of-n + leaves)."""

    kind: str  # "leaf" | "internal"
    attr: Optional[str] = None
    threshold: int = 1
    children: List["AccessTree"] = field(default_factory=list)
    index: int = 1


@dataclass
class PublicParams:
    Y: int
    V: int
    h_exp: int  # represent h = g^beta by beta (sim)
    beta: int
    alpha: int
    delta: int
    pk_attr: Dict[str, int] = field(default_factory=dict)  # t_a
    pk_role: Dict[str, int] = field(default_factory=dict)  # s_i + xi
    ar: Dict[str, int] = field(default_factory=dict)  # h_i
    s_i: Dict[str, int] = field(default_factory=dict)
    xi: int = 0


@dataclass
class UserAttrKeys:
    usk1_exp: int  # alpha + beta * r_u
    E_exp_g: int  # beta * r_u
    E_exp_h: int  # mu_u
    E1_exp: int  # mu_u
    E_ua: Dict[str, int]  # beta * r_u * inv(t_a)
    r_u: int
    mu_u: int
    attrs: List[str]


@dataclass
class UserRoleMaterial:
    rho: int
    D0_exp: int  # (1/beta) * (rho + Hp(ID)) * delta
    D1_exp: int  # alpha * rho
    user_id: str
    RK: Dict[str, int] = field(default_factory=dict)  # T_u / (s+xi)


@dataclass
class PartialAttrCT:
    C_tilde: int  # Z^A * Y^{s1}  (as GT int)
    C_prime_exp: int  # s1
    C_dprime_exp: int  # beta * s1
    s1: int
    ZA: int


@dataclass
class AttrCT:
    tree: AccessTree
    C_tilde: int
    C_prime_exp: int
    C_tilde_prime_exp: int  # s1 + s'
    C_tilde_dprime_exp: int  # beta*(s1+s')
    leaf_qx0: Dict[str, Tuple[str, int]]  # leaf_id -> (attr, qx0)
    C_a_exp: Dict[str, int]  # leaf_id -> t_a * qx0


@dataclass
class RoleEnvelope:
    target_role: str
    C1: int
    C2_exp: int  # beta * d
    C3_exp: Dict[str, int]  # rl -> h_l * d
    Ci_exp: int  # (s_i+xi)*d
    d: int


class SimulatedCrypto:
    """Algebraic simulator matching Section III equations."""

    def __init__(self) -> None:
        self.pp: Optional[PublicParams] = None
        self._t_a: Dict[str, int] = {}
        self._prev_t: Dict[str, int] = {}
        self._beta: int = 0
        self._alpha: int = 0
        self._delta: int = 0
        self._h_i: Dict[str, int] = {}
        self._s_i: Dict[str, int] = {}
        self._xi: int = 0
        self._rs: Dict[str, int] = {}

    def ca_setup(self) -> None:
        self._alpha = _rand_zp()
        self._delta = _rand_zp()
        # Y = e(g,g)^alpha = alpha (in exponent encoding of GT)
        self.pp = PublicParams(
            Y=self._alpha % _P,
            V=self._delta % _P,
            h_exp=0,
            beta=0,
            alpha=self._alpha,
            delta=self._delta,
        )

    def aa_setup(self, universe: Sequence[str]) -> None:
        assert self.pp is not None
        self._beta = _rand_zp()
        self.pp.beta = self._beta
        self.pp.h_exp = self._beta
        for a in universe:
            t = _rand_zp()
            self._t_a[a] = t
            self.pp.pk_attr[a] = t

    def role_setup(self, auth_paths: Dict[str, List[str]], role_order: Sequence[str]) -> None:
        assert self.pp is not None
        for rid in role_order:
            self._h_i[rid] = _rand_zp()
            self.pp.ar[rid] = self._h_i[rid]
        self._xi = 0
        for rid in role_order:
            s = sum(self._h_i[rk] for rk in auth_paths[rid]) % _P
            if s == 0:
                s = 1
            self._s_i[rid] = s
            self.pp.s_i[rid] = s
            sm = (s + self._xi) % _P
            if sm == 0:
                self._xi = 1
                sm = (s + self._xi) % _P
            self.pp.pk_role[rid] = sm
            self._rs[rid] = pow(sm, -1, _P)
        self.pp.xi = self._xi

    def aa_keygen(self, attrs: Sequence[str]) -> UserAttrKeys:
        r_u = _rand_zp()
        mu_u = _rand_zp()
        bru = (self._beta * r_u) % _P
        usk1 = (self._alpha + bru) % _P
        E_ua = {}
        for a in attrs:
            inv_t = pow(self._t_a[a], -1, _P)
            E_ua[a] = (bru * inv_t) % _P
        return UserAttrKeys(
            usk1_exp=usk1,
            E_exp_g=bru,
            E_exp_h=mu_u,
            E1_exp=mu_u,
            E_ua=E_ua,
            r_u=r_u,
            mu_u=mu_u,
            attrs=list(attrs),
        )

    def ca_role_user(self, user_id: str) -> UserRoleMaterial:
        rho = _rand_zp()
        hid = _hp(user_id)
        inv_beta = pow(self._beta, -1, _P)
        D0 = (inv_beta * ((rho + hid) % _P) * self._delta) % _P
        D1 = (self._alpha * rho) % _P
        return UserRoleMaterial(rho=rho, D0_exp=D0, D1_exp=D1, user_id=user_id)

    def rm_issue_rk(self, role_id: str, mat: UserRoleMaterial) -> int:
        hid = _hp(mat.user_id)
        Tu = (self._alpha * mat.rho + hid * self._delta) % _P
        rk = (Tu * self._rs[role_id]) % _P
        mat.RK[role_id] = rk
        return rk

    def sample_ZA(self) -> int:
        return _rand_zp()

    def sample_ZR(self) -> int:
        return _rand_zp()

    def gateway_partial_attr(self, ZA: int) -> PartialAttrCT:
        s1 = _rand_zp()
        # C_tilde = Z^A * Y^{s1}  encoded as (ZA + Y*s1) mod p in additive GT sim
        # Using additive GT: gT^x represented by x.
        C_tilde = (ZA + (self.pp.Y * s1)) % _P  # type: ignore[union-attr]
        return PartialAttrCT(
            C_tilde=C_tilde,
            C_prime_exp=s1,
            C_dprime_exp=(self._beta * s1) % _P,
            s1=s1,
            ZA=ZA,
        )

    def _assign(self, node: AccessTree, q0: int, leaf_qx0: Dict, C_a: Dict, path: str) -> None:
        if node.kind == "leaf":
            assert node.attr is not None
            lid = f"{path}:{node.attr}"
            leaf_qx0[lid] = (node.attr, q0)
            C_a[lid] = (self._t_a[node.attr] * q0) % _P
            return
        k = node.threshold
        coef = [q0] + [_rand_zp() for _ in range(k - 1)]
        for i, child in enumerate(node.children):
            child.index = i + 1
            x = child.index
            qx = 0
            xp = 1
            for c in coef:
                qx = (qx + c * xp) % _P
                xp = (xp * x) % _P
            self._assign(child, qx, leaf_qx0, C_a, f"{path}/{child.index}")

    def outsource_policy_encrypt(self, partial: PartialAttrCT, tree: AccessTree) -> AttrCT:
        s_prime = _rand_zp()
        leaf_qx0: Dict[str, Tuple[str, int]] = {}
        C_a: Dict[str, int] = {}
        self._assign(tree, s_prime, leaf_qx0, C_a, "R")
        return AttrCT(
            tree=tree,
            C_tilde=partial.C_tilde,
            C_prime_exp=partial.s1,
            C_tilde_prime_exp=(partial.s1 + s_prime) % _P,
            C_tilde_dprime_exp=(self._beta * ((partial.s1 + s_prime) % _P)) % _P,
            leaf_qx0=leaf_qx0,
            C_a_exp=C_a,
        )

    def _lagrange0(self, i: int, S: List[int]) -> int:
        num, den = 1, 1
        for j in S:
            if j == i:
                continue
            num = (num * ((-_P + 0 - j) % _P)) % _P
            den = (den * ((i - j) % _P)) % _P
        return (num * pow(den, -1, _P)) % _P

    def _eval(self, node: AccessTree, keys: UserAttrKeys, ct: AttrCT, path: str) -> Optional[int]:
        # Returns beta*r_u*q_x(0) in GT exponent encoding.
        if node.kind == "leaf":
            assert node.attr is not None
            lid = f"{path}:{node.attr}"
            if node.attr not in keys.E_ua or lid not in ct.C_a_exp:
                return None
            # e(E_ua, C_a) = (beta r / t) * (t q) = beta r q
            return (keys.E_ua[node.attr] * ct.C_a_exp[lid]) % _P
        good: List[Tuple[int, int]] = []
        for i, child in enumerate(node.children):
            val = self._eval(child, keys, ct, f"{path}/{i+1}")
            if val is not None:
                good.append((child.index, val))
        if len(good) < node.threshold:
            return None
        good = good[: node.threshold]
        S = [g[0] for g in good]
        acc = 0
        for idx, val in good:
            lag = self._lagrange0(idx, S)
            acc = (acc + val * lag) % _P
        return acc

    def outsource_attr_transform(self, ct: AttrCT, keys: UserAttrKeys) -> Optional[int]:
        FR = self._eval(ct.tree, keys, ct, "R")
        if FR is None:
            return None
        # B = e(E,~C') / (e(E1,~C'') FR)
        # e(E,~C') = E_exp_g * C_tilde_prime + E_exp_h * beta? Wait:
        # E = g^{beta r} h^{mu} = g^{beta r + beta mu} if h=g^beta => E_exp = beta(r+mu)
        # In our encoding E_exp_g = beta*r, E_exp_h = mu, and e(E, g^{s}) =
        # (beta*r + beta*mu)*s if we expand h=g^beta.
        # e(E1, h^{s}) = e(g^mu, g^{beta s}) = mu*beta*s
        # so e(E,g^s)/e(E1,h^s) = beta*r*s
        num = (keys.E_exp_g * ct.C_tilde_prime_exp + keys.E_exp_h * self._beta * ct.C_tilde_prime_exp) % _P
        den1 = (keys.E1_exp * ct.C_tilde_dprime_exp) % _P
        # C_tilde_dprime_exp already = beta*(s1+s'), E1=g^mu => e = mu*beta*(s1+s')
        Bj = (num - den1 - FR) % _P
        return Bj

    def user_recover_ZA(self, ct: AttrCT, Bj: int, usk1_exp: int) -> int:
        # Z = C_tilde * B / e(C', usk1)
        den = (ct.C_prime_exp * usk1_exp) % _P
        return (ct.C_tilde + Bj - den) % _P

    def role_encrypt(self, ZR: int, target: str, H_ri: Sequence[str]) -> RoleEnvelope:
        d = _rand_zp()
        # C1 = Z^R * (Y/V)^d = ZR + (Y-V)*d
        C1 = (ZR + ((self.pp.Y - self.pp.V) % _P) * d) % _P  # type: ignore[union-attr]
        C3 = {rl: (self._h_i[rl] * d) % _P for rl in H_ri}
        Ci = (self.pp.pk_role[target] * d) % _P  # type: ignore[union-attr]
        return RoleEnvelope(
            target_role=target,
            C1=C1,
            C2_exp=(self._beta * d) % _P,
            C3_exp=C3,
            Ci_exp=Ci,
            d=d,
        )

    def outsource_role_transform(
        self, env: RoleEnvelope, TR_exp: int, D0_exp: int, Gamma: Sequence[str]
    ) -> Tuple[int, int]:
        # prod = Ci * prod C3 = (s_i+xi)*d + sum h_l * d = (s_x + xi)*d
        prod = env.Ci_exp
        for rl in Gamma:
            prod = (prod + env.C3_exp[rl]) % _P
        P = (prod * TR_exp) % _P
        Q = (env.C2_exp * D0_exp) % _P
        return P, Q

    def user_recover_ZR(self, env: RoleEnvelope, P: int, Q: int, omega: int, rho: int) -> int:
        # Z = C1 / (P^{1/omega}/Q)^{1/rho}
        inv_omega = pow(omega, -1, _P)
        P1 = (P * inv_omega) % _P
        ratio = (P1 - Q) % _P
        inv_rho = pow(rho, -1, _P)
        mask = (ratio * inv_rho) % _P
        return (env.C1 - mask) % _P

    def make_TR(self, rk: int, omega: int) -> int:
        return (rk * omega) % _P

    def revoke_attribute(self, attr: str) -> None:
        self._prev_t[attr] = self._t_a[attr]
        self._t_a[attr] = _rand_zp()
        self.pp.pk_attr[attr] = self._t_a[attr]  # type: ignore[union-attr]

    def refresh_Eua(self, old_Eua: int, attr: str) -> int:
        # E_new = old ^{t_old / t_new}
        # old = beta r / t_old; new = old * t_old * inv(t_new) = beta r / t_new
        t_old = self._prev_t[attr]
        t_new = self._t_a[attr]
        return (old_Eua * t_old * pow(t_new, -1, _P)) % _P

    def refresh_xi(self) -> None:
        while True:
            xi = _rand_zp()
            if all((self._s_i[r] + xi) % _P != 0 for r in self._s_i):
                break
        self._xi = xi
        self.pp.xi = xi  # type: ignore[union-attr]
        for rid, s in self._s_i.items():
            sm = (s + xi) % _P
            self.pp.pk_role[rid] = sm  # type: ignore[union-attr]
            self._rs[rid] = pow(sm, -1, _P)
