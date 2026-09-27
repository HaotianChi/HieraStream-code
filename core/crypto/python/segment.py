"""Complete Section III cryptographic engine (standalone)."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .access_tree import AccessTree
from .field import Zp
from .groups import GElement, GTElement, PairingContext
from .hierarchy import RoleHierarchy
from .kdf_aead import aead_decrypt, aead_encrypt, derive_segment_key


# ---------------------------------------------------------------------------
# Public / secret containers with actor boundaries
# ---------------------------------------------------------------------------


@dataclass
class PublicParams:
    Y: GTElement  # e(g,g)^alpha
    V: GTElement  # e(g,g)^delta
    h: GElement  # g^beta
    pk_attr: Dict[str, GElement] = field(default_factory=dict)  # g^{t_a}
    ar: Dict[str, GElement] = field(default_factory=dict)  # AR_i = g^{h_i}
    pk_role: Dict[str, GElement] = field(default_factory=dict)  # g^{s_i+xi}


@dataclass
class CASecrets:
    alpha: Zp
    delta: Zp
    A: GElement  # g^alpha  → provisioned to AA
    W: GElement  # g^delta  → provisioned to RM
    F: Optional[GElement] = None  # g^{1/beta} ← from AA
    h_i: Dict[str, Zp] = field(default_factory=dict)
    s_i: Dict[str, Zp] = field(default_factory=dict)


@dataclass
class AASecrets:
    beta: Zp
    A: GElement
    t_a: Dict[str, Zp] = field(default_factory=dict)
    t_a_prev: Dict[str, Zp] = field(default_factory=dict)  # AA-private only


@dataclass
class RMSecrets:
    W: GElement
    xi: Zp
    s_i: Dict[str, Zp] = field(default_factory=dict)
    rs: Dict[str, Zp] = field(default_factory=dict)  # (s_i+xi)^{-1} RM-only


@dataclass
class SystemSecrets:
    ca: CASecrets
    aa: AASecrets
    rm: RMSecrets


@dataclass
class UserAttrMaterial:
    """Attribute-side keys. Storage boundaries per Eq.(7)."""

    user_id: str
    attrs: List[str]
    usk1: GElement  # USER ONLY
    E: GElement  # outsource
    E1: GElement  # outsource
    E_ua: Dict[str, GElement]  # outsource
    # AA-internal (never leave AA in real protocol; kept for refresh tests)
    _r_u: Zp = field(repr=False)
    _mu_u: Zp = field(repr=False)

    def to_outsource_keys(self) -> "OutsourceAttrKeys":
        return OutsourceAttrKeys(
            user_id=self.user_id, E=self.E, E1=self.E1, E_ua=dict(self.E_ua)
        )


@dataclass
class UserRoleMaterial:
    user_id: str
    rho: Zp  # USER ONLY
    D0: GElement  # outsource
    D1: GElement  # RM
    RK: Dict[str, GElement] = field(default_factory=dict)  # issued by RM


@dataclass
class PartialAttrCT:
    C_tilde: GTElement
    C_prime: GElement
    C_dprime: GElement
    s1: Zp = field(repr=False)
    ZA: GTElement = field(repr=False)

    def to_outsource_view(self) -> "OutsourcePartialAttrCT":
        """Paper III-B: outsource must not learn Z^A (or s1)."""
        return OutsourcePartialAttrCT(
            C_tilde=self.C_tilde, C_prime=self.C_prime, C_dprime=self.C_dprime
        )


@dataclass(frozen=True)
class OutsourcePartialAttrCT:
    """Public partial attribute CT components only (Eq. 13 public parts)."""

    C_tilde: GTElement
    C_prime: GElement
    C_dprime: GElement


@dataclass(frozen=True)
class OutsourceAttrKeys:
    """Outsource-visible attribute material only — never U_sk,1 / r_u / μ_u (Eq. 7)."""

    user_id: str
    E: GElement
    E1: GElement
    E_ua: Dict[str, GElement]


@dataclass
class AttrCT:
    tree: AccessTree
    C_tilde: GTElement
    C_prime: GElement
    C_tilde_prime: GElement
    C_tilde_dprime: GElement
    C_a: Dict[str, GElement]  # leaf_id -> C_{j,a}


@dataclass
class RoleEnvelope:
    target_role: str
    C1: GTElement
    C2: GElement
    C3: Dict[str, GElement]
    Ci: GElement
    d: Zp  # for tests verifying independence; not transmitted in real CT


@dataclass
class ProtectedSegmentCrypto:
    ZA: GTElement
    ZR: GTElement
    key: bytes
    ct_aes: bytes
    attr_ct: AttrCT
    role_envelopes: List[RoleEnvelope]
    targets: List[str]


class SegmentCrypto:
    """Full dual-layer cryptographic construction (Section III).

    backend: "algebraic" (default) | "pbc" / "native"
    Also honors HIERASTREAM_CRYPTO_BACKEND.
    """

    def __init__(self, backend: Optional[str] = None) -> None:
        import os

        chosen = (backend or os.environ.get("HIERASTREAM_CRYPTO_BACKEND") or "algebraic").lower()
        if chosen in ("pbc", "native"):
            from . import pbc_field as _field
            from . import pbc_groups as _groups

            self.backend = "pbc"
            self.Zp = _field.Zp
            self.GElement = _groups.GElement
            self.GTElement = _groups.GTElement
            self.ctx = _groups.PairingContext()
        else:
            self.backend = "algebraic"
            self.Zp = Zp
            self.GElement = GElement
            self.GTElement = GTElement
            self.ctx = PairingContext()
        self.pp: Optional[PublicParams] = None
        self.secrets: Optional[SystemSecrets] = None
        self.hierarchy: Optional[RoleHierarchy] = None

    # ------------------------------------------------------------------
    # B. System setup
    # ------------------------------------------------------------------
    def ca_setup(self) -> None:
        alpha = self.Zp.random()
        delta = self.Zp.random()
        A = self.ctx.g_pow(alpha)
        W = self.ctx.g_pow(delta)
        Y = self.ctx.gt_pow_gg(alpha)
        V = self.ctx.gt_pow_gg(delta)
        ca = CASecrets(alpha=alpha, delta=delta, A=A, W=W)
        # AA/RM placeholders until their setup
        aa = AASecrets(beta=self.Zp.one(), A=A)
        rm = RMSecrets(W=W, xi=self.Zp.zero())
        self.secrets = SystemSecrets(ca=ca, aa=aa, rm=rm)
        self.pp = PublicParams(Y=Y, V=V, h=self.GElement.identity())

    def aa_setup(self, universe: Sequence[str]) -> None:
        assert self.secrets and self.pp
        beta = self.Zp.random()
        self.secrets.aa.beta = beta
        self.secrets.aa.A = self.secrets.ca.A
        h = self.ctx.g_pow(beta)
        self.pp.h = h
        inv_beta = beta.inv()
        self.secrets.ca.F = self.ctx.g_pow(inv_beta)
        for a in universe:
            t = self.Zp.random()
            self.secrets.aa.t_a[a] = t
            self.pp.pk_attr[a] = self.ctx.g_pow(t)

    def role_setup(self, hierarchy: RoleHierarchy) -> None:
        assert self.secrets and self.pp
        hierarchy.validate_nesting()
        self.hierarchy = hierarchy
        ca, rm = self.secrets.ca, self.secrets.rm
        for rid in hierarchy.role_order:
            hi = self.Zp.random()
            ca.h_i[rid] = hi
            self.pp.ar[rid] = self.ctx.g_pow(hi)
        rm.xi = self.Zp.zero()
        for rid in hierarchy.role_order:
            s = self.Zp.zero()
            for rk in hierarchy.auth_path(rid):
                s = s + ca.h_i[rk]
            if s.is_zero():
                # Extremely unlikely with random h; force nonzero path sum
                s = self.Zp.one()
            ca.s_i[rid] = s
            rm.s_i[rid] = s
            sm = s + rm.xi
            while sm.is_zero():
                rm.xi = self.Zp.random()
                sm = s + rm.xi
            self.pp.pk_role[rid] = self.ctx.g_pow(sm)
            rm.rs[rid] = sm.inv()

    # ------------------------------------------------------------------
    # D. User provisioning
    # ------------------------------------------------------------------
    def aa_keygen(self, user_id: str, attrs: Sequence[str]) -> UserAttrMaterial:
        assert self.secrets and self.pp
        aa = self.secrets.aa
        r_u = self.Zp.random()
        mu_u = self.Zp.random()
        # U_sk,1 = A * h^{r_u}
        usk1 = aa.A.mul(self.pp.h.pow(r_u))
        # E = g^{beta r_u} * h^{mu_u}
        g_bru = self.ctx.g_pow(aa.beta * r_u)
        E = g_bru.mul(self.pp.h.pow(mu_u))
        E1 = self.ctx.g_pow(mu_u)
        E_ua: Dict[str, GElement] = {}
        for a in attrs:
            inv_t = aa.t_a[a].inv()
            E_ua[a] = self.ctx.g_pow(aa.beta * r_u * inv_t)
        return UserAttrMaterial(
            user_id=user_id,
            attrs=list(attrs),
            usk1=usk1,
            E=E,
            E1=E1,
            E_ua=E_ua,
            _r_u=r_u,
            _mu_u=mu_u,
        )

    def outsource_attr_keys(self, mat: UserAttrMaterial) -> OutsourceAttrKeys:
        return OutsourceAttrKeys(user_id=mat.user_id, E=mat.E, E1=mat.E1, E_ua=dict(mat.E_ua))

    def ca_role_user(self, user_id: str) -> UserRoleMaterial:
        assert self.secrets and self.secrets.ca.F is not None
        ca = self.secrets.ca
        rho = self.Zp.random()
        hid = self.Zp.hash_to_zp(user_id.encode("utf-8"))
        # D0 = F^{[rho + Hp(ID)] delta}
        inner = (rho + hid) * ca.delta
        D0 = ca.F.pow(inner)
        D1 = ca.A.pow(rho)
        return UserRoleMaterial(user_id=user_id, rho=rho, D0=D0, D1=D1)

    def rm_issue_rk(self, role_id: str, mat: UserRoleMaterial) -> GElement:
        assert self.secrets
        rm = self.secrets.rm
        hid = self.Zp.hash_to_zp(mat.user_id.encode("utf-8"))
        # RK = (D1 * W^{Hp(ID)})^{RS}
        base = mat.D1.mul(rm.W.pow(hid))
        rk = base.pow(rm.rs[role_id])
        mat.RK[role_id] = rk
        return rk

    # ------------------------------------------------------------------
    # E–G Attribute encryption / decryption
    # ------------------------------------------------------------------
    def sample_ZA(self) -> GTElement:
        return self.ctx.sample_gt()

    def sample_ZR(self) -> GTElement:
        return self.ctx.sample_gt()

    def gateway_partial_attr(self, ZA: GTElement) -> PartialAttrCT:
        """Fixed-size gateway work — independent of policy size. Eq.(13)."""
        assert self.pp
        s1 = self.Zp.random()
        C_tilde = ZA.mul(self.pp.Y.pow(s1))
        C_prime = self.ctx.g_pow(s1)
        C_dprime = self.pp.h.pow(s1)
        return PartialAttrCT(C_tilde=C_tilde, C_prime=C_prime, C_dprime=C_dprime, s1=s1, ZA=ZA)

    def _assign_poly(
        self,
        node: AccessTree,
        q0: Zp,
        C_a: Dict[str, GElement],
        path: str,
    ) -> None:
        assert self.pp and self.secrets
        if node.kind == "leaf":
            assert node.attr is not None
            lid = f"{path}:{node.attr}"
            C_a[lid] = self.pp.pk_attr[node.attr].pow(q0)
            return
        k = node.threshold
        coef = [q0] + [self.Zp.random() for _ in range(k - 1)]
        for i, child in enumerate(node.children):
            child.index = i + 1
            x = self.Zp.from_int(child.index)
            qx = self.Zp.zero()
            xp = self.Zp.one()
            for c in coef:
                qx = qx + c * xp
                xp = xp * x
            self._assign_poly(child, qx, C_a, f"{path}/{child.index}")

    def outsource_policy_encrypt(
        self, partial: PartialAttrCT | OutsourcePartialAttrCT, tree: AccessTree
    ) -> AttrCT:
        """Policy-size-dependent outsourced encryption. Eqs.(14)–(16).

        Accepts only public partial components. If a full PartialAttrCT is passed,
        secrets Z^A/s1 are stripped before use (outsource must not learn them).
        """
        assert self.pp
        view = partial.to_outsource_view() if isinstance(partial, PartialAttrCT) else partial
        tree = deepcopy(tree)
        s_prime = self.Zp.random()
        C_a: Dict[str, GElement] = {}
        self._assign_poly(tree, s_prime, C_a, "R")
        C_tilde_prime = view.C_prime.mul(self.ctx.g_pow(s_prime))
        C_tilde_dprime = view.C_dprime.mul(self.pp.h.pow(s_prime))
        return AttrCT(
            tree=tree,
            C_tilde=view.C_tilde,
            C_prime=view.C_prime,
            C_tilde_prime=C_tilde_prime,
            C_tilde_dprime=C_tilde_dprime,
            C_a=C_a,
        )

    def _lagrange0(self, i: int, S: List[int]) -> Zp:
        num, den = self.Zp.one(), self.Zp.one()
        xi = self.Zp.from_int(i)
        for j in S:
            if j == i:
                continue
            xj = self.Zp.from_int(j)
            num = num * (-xj)
            den = den * (xi - xj)
        return num * den.inv()

    def _eval_tree(
        self,
        node: AccessTree,
        keys: UserAttrMaterial | OutsourceAttrKeys,
        ct: AttrCT,
        path: str,
    ) -> Optional[GTElement]:
        """Returns e(g,g)^{beta r_u q_x(0)} or None."""
        assert self.ctx
        if node.kind == "leaf":
            assert node.attr is not None
            lid = f"{path}:{node.attr}"
            if node.attr not in keys.E_ua or lid not in ct.C_a:
                return None
            return self.ctx.pairing(keys.E_ua[node.attr], ct.C_a[lid])
        good: List[Tuple[int, GTElement]] = []
        for i, child in enumerate(node.children):
            val = self._eval_tree(child, keys, ct, f"{path}/{i+1}")
            if val is not None:
                good.append((child.index, val))
        if len(good) < node.threshold:
            return None
        good = good[: node.threshold]
        S = [g[0] for g in good]
        acc = self.GTElement.identity()
        for idx, val in good:
            lag = self._lagrange0(idx, S)
            acc = acc.mul(val.pow(lag))
        return acc

    def outsource_attr_transform(
        self, ct: AttrCT, keys: UserAttrMaterial | OutsourceAttrKeys
    ) -> Optional[GTElement]:
        """Returns B_j. Must NOT receive usk1. Eq.(27)."""
        assert self.ctx
        if isinstance(keys, UserAttrMaterial):
            keys = keys.to_outsource_keys()
        FR = self._eval_tree(ct.tree, keys, ct, "R")
        if FR is None:
            return None
        num = self.ctx.pairing(keys.E, ct.C_tilde_prime)
        den1 = self.ctx.pairing(keys.E1, ct.C_tilde_dprime)
        den = den1.mul(FR)
        return num.mul(den.inv())

    def user_recover_ZA(self, ct: AttrCT, Bj: GTElement, usk1: GElement) -> GTElement:
        """Eq.(28). User-side only."""
        assert self.ctx
        num = ct.C_tilde.mul(Bj)
        den = self.ctx.pairing(ct.C_prime, usk1)
        return num.mul(den.inv())

    # ------------------------------------------------------------------
    # H–I Role encryption / decryption
    # ------------------------------------------------------------------
    def role_encrypt(self, ZR: GTElement, target: str) -> RoleEnvelope:
        assert self.pp and self.hierarchy
        H_ri = self.hierarchy.H(target)
        d = self.Zp.random()
        # C1 = Z^R * (Y/V)^d
        YoverV = self.pp.Y.mul(self.pp.V.inv())
        C1 = ZR.mul(YoverV.pow(d))
        C2 = self.pp.h.pow(d)
        C3 = {rl: self.pp.ar[rl].pow(d) for rl in H_ri}
        Ci = self.pp.pk_role[target].pow(d)
        return RoleEnvelope(target_role=target, C1=C1, C2=C2, C3=C3, Ci=Ci, d=d)

    def role_encrypt_multi(self, ZR: GTElement, targets: Sequence[str]) -> List[RoleEnvelope]:
        """Independent d_{i,j} per target; same Z^R. Eqs.(17)–(21)."""
        return [self.role_encrypt(ZR, t) for t in targets]

    def make_TR(self, rk: GElement, omega: Zp) -> GElement:
        return rk.pow(omega)

    def outsource_role_transform(
        self,
        env: RoleEnvelope,
        TR: GElement,
        D0: GElement,
        Gamma: Sequence[str],
    ) -> Tuple[GTElement, GTElement]:
        """Eq.(33): P, Q."""
        assert self.ctx
        prod = env.Ci
        for rl in Gamma:
            prod = prod.mul(env.C3[rl])
        P = self.ctx.pairing(prod, TR)
        Q = self.ctx.pairing(env.C2, D0)
        return P, Q

    def user_recover_ZR(
        self, env: RoleEnvelope, P: GTElement, Q: GTElement, omega: Zp, rho: Zp
    ) -> GTElement:
        """Eq.(34)."""
        inv_omega = omega.inv()
        P1 = P.pow(inv_omega)
        ratio = P1.mul(Q.inv())
        mask = ratio.pow(rho.inv())
        return env.C1.mul(mask.inv())

    # ------------------------------------------------------------------
    # E + J Segment protect / recover
    # ------------------------------------------------------------------
    def protect_segment(
        self,
        plaintext: bytes,
        tree: AccessTree,
        targets: Sequence[str],
        aad: bytes = b"",
    ) -> ProtectedSegmentCrypto:
        ZA = self.sample_ZA()
        ZR = self.sample_ZR()
        key = derive_segment_key(ZA, ZR)
        ct_aes = aead_encrypt(key, plaintext, aad=aad)
        partial = self.gateway_partial_attr(ZA)
        attr_ct = self.outsource_policy_encrypt(partial.to_outsource_view(), tree)
        envelopes = self.role_encrypt_multi(ZR, targets)
        return ProtectedSegmentCrypto(
            ZA=ZA,
            ZR=ZR,
            key=key,
            ct_aes=ct_aes,
            attr_ct=attr_ct,
            role_envelopes=envelopes,
            targets=list(targets),
        )

    def recover_segment(
        self,
        seg: ProtectedSegmentCrypto,
        attr_keys: UserAttrMaterial,
        role_mat: UserRoleMaterial,
        assigned_roles: Sequence[str],
        aad: bytes = b"",
    ) -> bytes:
        # Attribute path
        Bj = self.outsource_attr_transform(seg.attr_ct, attr_keys)
        if Bj is None:
            raise PermissionError("attribute policy not satisfied")
        # Boundary: transform used E/E1/E_ua only; usk1 only here
        ZA = self.user_recover_ZA(seg.attr_ct, Bj, attr_keys.usk1)

        # Role path
        assert self.hierarchy
        chosen: Optional[RoleEnvelope] = None
        assigned: Optional[str] = None
        for ri in seg.targets:
            for rx in assigned_roles:
                if self.hierarchy.dominates(rx, ri) and rx in role_mat.RK:
                    chosen = next(e for e in seg.role_envelopes if e.target_role == ri)
                    assigned = rx
                    break
            if chosen:
                break
        if chosen is None or assigned is None:
            raise PermissionError("no authorized role")

        omega = self.Zp.random()
        TR = self.make_TR(role_mat.RK[assigned], omega)
        Gamma = self.hierarchy.Gamma(assigned, chosen.target_role)
        P, Q = self.outsource_role_transform(chosen, TR, role_mat.D0, Gamma)
        ZR = self.user_recover_ZR(chosen, P, Q, omega, role_mat.rho)

        key = derive_segment_key(ZA, ZR)
        return aead_decrypt(key, seg.ct_aes, aad=aad)

    # ------------------------------------------------------------------
    # Attribute revocation helpers (crypto-level)
    # ------------------------------------------------------------------
    def aa_revoke_attribute(self, attr: str) -> None:
        assert self.secrets and self.pp
        aa = self.secrets.aa
        aa.t_a_prev[attr] = aa.t_a[attr]
        t_new = self.Zp.random()
        aa.t_a[attr] = t_new
        self.pp.pk_attr[attr] = self.ctx.g_pow(t_new)

    def aa_refresh_Eua(self, old: GElement, attr: str) -> GElement:
        """E_new = old^{t_old/t_new}. Ratio never returned/logged."""
        assert self.secrets
        aa = self.secrets.aa
        t_old = aa.t_a_prev[attr]
        t_new = aa.t_a[attr]
        ratio = t_old * t_new.inv()
        return old.pow(ratio)

    def rm_refresh_xi(self) -> None:
        assert self.secrets and self.pp
        rm = self.secrets.rm
        while True:
            xi = self.Zp.random()
            if all(not (s + xi).is_zero() for s in rm.s_i.values()):
                break
        rm.xi = xi
        for rid, s in rm.s_i.items():
            sm = s + xi
            self.pp.pk_role[rid] = self.ctx.g_pow(sm)
            rm.rs[rid] = sm.inv()
