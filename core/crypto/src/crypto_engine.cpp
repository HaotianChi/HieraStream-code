#include "hierastream/crypto_engine.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <functional>
#include <map>
#include <stdexcept>

namespace hierastream {

namespace {

Element zr_int(PairingContext& ctx, long v) {
  Element e(ctx, 3);
  element_set_si(e.raw(), v);
  return e;
}

// Lagrange coefficient Δ_i,S(0) in Zr.
Element lagrange_at_zero(PairingContext& ctx, int i, const std::vector<int>& S) {
  Element num = zr_int(ctx, 1);
  Element den = zr_int(ctx, 1);
  Element xi = zr_int(ctx, i);
  for (int j : S) {
    if (j == i) {
      continue;
    }
    Element xj = zr_int(ctx, j);
    Element term_n(ctx, 3);
    element_neg(term_n.raw(), xj.raw());  // 0 - xj
    Element term_d(ctx, 3);
    element_sub(term_d.raw(), xi.raw(), xj.raw());
    element_mul(num.raw(), num.raw(), term_n.raw());
    element_mul(den.raw(), den.raw(), term_d.raw());
  }
  Element inv(ctx, 3);
  inv.invert(den);
  Element out(ctx, 3);
  out.mul(num, inv);
  return out;
}

}  // namespace

CryptoEngine::CryptoEngine(const std::string& param_path) : ctx_(param_path) {
  pp_.g = Element(ctx_, 0);
  element_random(pp_.g.raw());  // generator candidate
}

void CryptoEngine::ca_setup() {
  ca_.alpha = Element(ctx_, 3);
  ca_.delta = Element(ctx_, 3);
  ca_.alpha.set_random();
  ca_.delta.set_random();

  ca_.A = Element(ctx_, 0);
  ca_.A.pow_zn(pp_.g, ca_.alpha);

  Element tmp(ctx_, 0);
  tmp.pow_zn(pp_.g, ca_.delta);
  pp_.W = tmp;

  // Y = e(g,g)^alpha, V = e(g,g)^delta  Eq.(2)
  Element gg(ctx_, 2);
  gg.pairing(pp_.g, pp_.g);
  pp_.Y = Element(ctx_, 2);
  pp_.Y.pow_zn(gg, ca_.alpha);
  pp_.V = Element(ctx_, 2);
  pp_.V.pow_zn(gg, ca_.delta);

  rm_.W = pp_.W;
  rm_.xi = Element(ctx_, 3);
  element_set0(rm_.xi.raw());  // xi_0 = 0
  ca_ready_ = true;
}

void CryptoEngine::aa_setup(const std::vector<std::string>& universe) {
  if (!ca_ready_) {
    throw std::runtime_error("CA setup required before AA setup");
  }
  aa_.beta = Element(ctx_, 3);
  aa_.beta.set_random();
  aa_.A = ca_.A;

  pp_.h = Element(ctx_, 0);
  pp_.h.pow_zn(pp_.g, aa_.beta);

  // F = g^{1/beta} provisioned to CA  Eq.(3)
  Element inv_beta(ctx_, 3);
  inv_beta.invert(aa_.beta);
  ca_.F = Element(ctx_, 0);
  ca_.F.pow_zn(pp_.g, inv_beta);

  for (const auto& a : universe) {
    Element t(ctx_, 3);
    t.set_random();
    aa_.t_a[a] = t;
    Element pk(ctx_, 0);
    pk.pow_zn(pp_.g, t);
    pp_.pk_attr[a] = pk;
  }
  aa_ready_ = true;
}

void CryptoEngine::role_setup(
    const std::map<std::string, std::vector<std::string>>& auth_paths,
    const std::vector<std::string>& role_order) {
  if (!ca_ready_) {
    throw std::runtime_error("CA setup required before role setup");
  }
  for (const auto& rid : role_order) {
    Element hi(ctx_, 3);
    hi.set_random();
    ca_.h_i[rid] = hi;
    Element ari(ctx_, 0);
    ari.pow_zn(pp_.g, hi);
    pp_.ar[rid] = ari;
  }
  for (const auto& rid : role_order) {
    const auto it = auth_paths.find(rid);
    if (it == auth_paths.end()) {
      throw std::runtime_error("missing authorization path for role " + rid);
    }
    Element si(ctx_, 3);
    element_set0(si.raw());
    for (const auto& rk : it->second) {
      element_add(si.raw(), si.raw(), ca_.h_i.at(rk).raw());
    }
    ca_.s_i[rid] = si;
    rm_.s_i[rid] = si;

    Element sum(ctx_, 3);
    element_add(sum.raw(), si.raw(), rm_.xi.raw());
    // Enforce s_i + xi != 0
    while (element_is0(sum.raw())) {
      rm_.xi.set_random();
      element_add(sum.raw(), si.raw(), rm_.xi.raw());
    }
    Element pk(ctx_, 0);
    pk.pow_zn(pp_.g, sum);
    pp_.pk_role[rid] = pk;
    Element rs(ctx_, 3);
    rs.invert(sum);
    rm_.rs[rid] = rs;
  }
  roles_ready_ = true;
}

Element CryptoEngine::hash_to_zr(const std::string& s) {
  Element z(ctx_, 3);
  z.set_zr_from_hash(reinterpret_cast<const uint8_t*>(s.data()), s.size());
  return z;
}

Element CryptoEngine::sample_gt() {
  Element z(ctx_, 2);
  z.set_random();
  return z;
}

Element CryptoEngine::sample_zr() {
  Element z(ctx_, 3);
  z.set_random();
  return z;
}

Element CryptoEngine::g_pow(const Element& exp) {
  Element out(ctx_, 0);
  out.pow_zn(pp_.g, exp);
  return out;
}

UserAttrKeys CryptoEngine::aa_keygen_user(const std::vector<std::string>& attrs) {
  if (!aa_ready_) {
    throw std::runtime_error("AA not ready");
  }
  UserAttrKeys uk;
  uk.r_u = Element(ctx_, 3);
  uk.mu_u = Element(ctx_, 3);
  uk.r_u.set_random();
  uk.mu_u.set_random();

  // U_sk,1 = A * h^{r_u} = g^{alpha + beta r_u}  Eq.(7)
  Element h_ru(ctx_, 0);
  h_ru.pow_zn(pp_.h, uk.r_u);
  uk.usk1 = Element(ctx_, 0);
  uk.usk1.mul(aa_.A, h_ru);

  // E = g^{beta r_u} * h^{mu_u}
  Element g_bru(ctx_, 0);
  Element bru(ctx_, 3);
  element_mul(bru.raw(), aa_.beta.raw(), uk.r_u.raw());
  g_bru.pow_zn(pp_.g, bru);
  Element h_mu(ctx_, 0);
  h_mu.pow_zn(pp_.h, uk.mu_u);
  uk.E = Element(ctx_, 0);
  uk.E.mul(g_bru, h_mu);

  uk.E1 = Element(ctx_, 0);
  uk.E1.pow_zn(pp_.g, uk.mu_u);

  for (const auto& a : attrs) {
    Element inv_t(ctx_, 3);
    inv_t.invert(aa_.t_a.at(a));
    Element exp(ctx_, 3);
    element_mul(exp.raw(), bru.raw(), inv_t.raw());
    Element Ea(ctx_, 0);
    Ea.pow_zn(pp_.g, exp);
    uk.E_ua[a] = Ea;
  }
  return uk;
}

UserRoleMaterial CryptoEngine::ca_role_user_material(const std::string& user_id) {
  UserRoleMaterial m;
  m.rho_u = Element(ctx_, 3);
  m.rho_u.set_random();
  Element hid = hash_to_zr(user_id);

  // D0 = F^{[rho + Hp(ID)] delta}  Eq.(8)
  Element inner(ctx_, 3);
  element_add(inner.raw(), m.rho_u.raw(), hid.raw());
  element_mul(inner.raw(), inner.raw(), ca_.delta.raw());
  m.D0 = Element(ctx_, 0);
  m.D0.pow_zn(ca_.F, inner);

  // D1 = A^{rho}
  m.D1 = Element(ctx_, 0);
  m.D1.pow_zn(ca_.A, m.rho_u);
  return m;
}

Element CryptoEngine::rm_issue_rk(const std::string& role_id,
                                  const Element& D1,
                                  const std::string& user_id) {
  Element hid = hash_to_zr(user_id);
  Element W_h(ctx_, 0);
  W_h.pow_zn(rm_.W, hid);
  Element base(ctx_, 0);
  base.mul(D1, W_h);
  Element rk(ctx_, 0);
  rk.pow_zn(base, rm_.rs.at(role_id));
  return rk;
}

PartialAttrCT CryptoEngine::gateway_partial_attr_encrypt(const Element& ZA) {
  // Fixed-size gateway work — independent of policy size. Eq.(13)
  PartialAttrCT p;
  p.ZA = ZA;
  p.s1 = Element(ctx_, 3);
  p.s1.set_random();

  Element Ys(ctx_, 2);
  Ys.pow_zn(pp_.Y, p.s1);
  p.C_tilde = Element(ctx_, 2);
  p.C_tilde.mul(ZA, Ys);

  p.C_prime = Element(ctx_, 0);
  p.C_prime.pow_zn(pp_.g, p.s1);

  p.C_dprime = Element(ctx_, 0);
  p.C_dprime.pow_zn(pp_.h, p.s1);
  return p;
}

void CryptoEngine::assign_polynomials(AccessTreeNode& node,
                                      const Element& q0,
                                      AttrCT& out,
                                      const std::string& path_id) {
  if (node.kind == AccessTreeNode::Kind::Leaf) {
    Element share = q0;
    std::string leaf_id = path_id + ":" + node.attr;
    Element Ca(ctx_, 0);
    Ca.pow_zn(pp_.pk_attr.at(node.attr), share);
    out.C_a[leaf_id] = Ca;
    out.leaf_shares[leaf_id] = {node.attr, share};
    return;
  }

  const int k = node.threshold;
  const int n = static_cast<int>(node.children.size());
  if (k < 1 || k > n) {
    throw std::runtime_error("invalid threshold gate");
  }
  std::vector<Element> coef;
  coef.push_back(q0);
  for (int i = 1; i < k; ++i) {
    Element c(ctx_, 3);
    c.set_random();
    coef.push_back(c);
  }

  for (int i = 0; i < n; ++i) {
    node.children[i].index = i + 1;
    // Evaluate polynomial at x = index
    Element x = zr_int(ctx_, node.children[i].index);
    Element qx(ctx_, 3);
    element_set0(qx.raw());
    Element xpow = zr_int(ctx_, 1);
    for (int d = 0; d < k; ++d) {
      Element term(ctx_, 3);
      element_mul(term.raw(), coef[d].raw(), xpow.raw());
      element_add(qx.raw(), qx.raw(), term.raw());
      element_mul(xpow.raw(), xpow.raw(), x.raw());
    }
    assign_polynomials(node.children[i], qx, out, path_id + "/" + std::to_string(i + 1));
  }
}

AttrCT CryptoEngine::outsource_policy_encrypt(const PartialAttrCT& partial,
                                              const AccessTreeNode& tree_in) {
  AttrCT ct;
  ct.tree = tree_in;
  ct.C_tilde = partial.C_tilde;
  ct.C_prime = partial.C_prime;

  Element s_prime(ctx_, 3);
  s_prime.set_random();

  Element gsp(ctx_, 0);
  gsp.pow_zn(pp_.g, s_prime);
  ct.C_tilde_prime = Element(ctx_, 0);
  ct.C_tilde_prime.mul(partial.C_prime, gsp);

  Element hsp(ctx_, 0);
  hsp.pow_zn(pp_.h, s_prime);
  ct.C_tilde_dprime = Element(ctx_, 0);
  ct.C_tilde_dprime.mul(partial.C_dprime, hsp);

  assign_polynomials(ct.tree, s_prime, ct, "R");
  return ct;
}

std::optional<Element> CryptoEngine::outsource_attr_transform(const AttrCT& ct,
                                                             const UserAttrKeys& keys) {
  // Recursive tree evaluation returning e(g,g)^{beta r_u q_x(0)} or nullopt.
  std::function<std::optional<Element>(const AccessTreeNode&, const std::string&)> eval =
      [&](const AccessTreeNode& node, const std::string& path_id) -> std::optional<Element> {
        if (node.kind == AccessTreeNode::Kind::Leaf) {
          std::string leaf_id = path_id + ":" + node.attr;
          auto kit = keys.E_ua.find(node.attr);
          auto cit = ct.C_a.find(leaf_id);
          if (kit == keys.E_ua.end() || cit == ct.C_a.end()) {
            return std::nullopt;
          }
          Element Fx(ctx_, 2);
          Fx.pairing(kit->second, cit->second);
          return Fx;
        }
        std::vector<std::pair<int, Element>> good;
        for (size_t i = 0; i < node.children.size(); ++i) {
          auto child = eval(node.children[i], path_id + "/" + std::to_string(i + 1));
          if (child) {
            good.emplace_back(node.children[i].index, *child);
          }
        }
        if (static_cast<int>(good.size()) < node.threshold) {
          return std::nullopt;
        }
        good.resize(static_cast<size_t>(node.threshold));
        std::vector<int> S;
        for (const auto& g : good) {
          S.push_back(g.first);
        }
        Element Fx(ctx_, 2);
        Fx.set_one();
        for (const auto& g : good) {
          Element lag = lagrange_at_zero(ctx_, g.first, S);
          Element powered(ctx_, 2);
          powered.pow_zn(g.second, lag);
          Element tmp(ctx_, 2);
          tmp.mul(Fx, powered);
          Fx = tmp;
        }
        return Fx;
      };

  auto FR = eval(ct.tree, "R");
  if (!FR) {
    return std::nullopt;
  }

  // B_j = e(E, ~C'_j) / (e(E1, ~C''_j) * F_R)  Eq.(27)
  Element num(ctx_, 2);
  num.pairing(keys.E, ct.C_tilde_prime);
  Element den1(ctx_, 2);
  den1.pairing(keys.E1, ct.C_tilde_dprime);
  Element den(ctx_, 2);
  den.mul(den1, *FR);
  Element Bj(ctx_, 2);
  Bj.div(num, den);
  return Bj;
}

Element CryptoEngine::user_recover_ZA(const AttrCT& ct, const Element& Bj, const Element& usk1) {
  // Z^A = (~C_j * B_j) / e(C'_j, U_sk,1)  Eq.(28)
  Element num(ctx_, 2);
  num.mul(ct.C_tilde, Bj);
  Element den(ctx_, 2);
  den.pairing(ct.C_prime, usk1);
  Element ZA(ctx_, 2);
  ZA.div(num, den);
  return ZA;
}

RoleEnvelope CryptoEngine::gateway_role_encrypt(const Element& ZR,
                                                const std::string& target_role,
                                                const std::vector<std::string>& H_ri) {
  RoleEnvelope env;
  env.target_role = target_role;
  Element d(ctx_, 3);
  d.set_random();

  // C1 = Z^R * (Y/V)^d  Eq.(19)
  Element YoverV(ctx_, 2);
  YoverV.div(pp_.Y, pp_.V);
  Element mask(ctx_, 2);
  mask.pow_zn(YoverV, d);
  env.C1 = Element(ctx_, 2);
  env.C1.mul(ZR, mask);

  env.C2 = Element(ctx_, 0);
  env.C2.pow_zn(pp_.h, d);

  for (const auto& rl : H_ri) {
    Element c3(ctx_, 0);
    c3.pow_zn(pp_.ar.at(rl), d);
    env.C3[rl] = c3;
  }

  env.Ci = Element(ctx_, 0);
  env.Ci.pow_zn(pp_.pk_role.at(target_role), d);
  return env;
}

std::pair<Element, Element> CryptoEngine::outsource_role_transform(
    const RoleEnvelope& env,
    const Element& TR,
    const Element& D0,
    const std::vector<std::string>& Gamma) {
  // P = e( Ci * prod C3l , TR )  Eq.(33)
  Element prod = env.Ci;
  for (const auto& rl : Gamma) {
    Element tmp(ctx_, 0);
    tmp.mul(prod, env.C3.at(rl));
    prod = tmp;
  }
  Element P(ctx_, 2);
  P.pairing(prod, TR);
  Element Q(ctx_, 2);
  Q.pairing(env.C2, D0);
  return {P, Q};
}

Element CryptoEngine::user_recover_ZR(const RoleEnvelope& env,
                                      const Element& P,
                                      const Element& Q,
                                      const Element& omega,
                                      const Element& rho) {
  // Z^R = C1 / (P^{1/omega} / Q)^{1/rho}  Eq.(34)
  Element inv_omega(ctx_, 3);
  inv_omega.invert(omega);
  Element P1(ctx_, 2);
  P1.pow_zn(P, inv_omega);
  Element ratio(ctx_, 2);
  ratio.div(P1, Q);
  Element inv_rho(ctx_, 3);
  inv_rho.invert(rho);
  Element mask(ctx_, 2);
  mask.pow_zn(ratio, inv_rho);
  Element ZR(ctx_, 2);
  ZR.div(env.C1, mask);
  return ZR;
}

void CryptoEngine::aa_revoke_attribute(const std::string& attr) {
  last_revoked_old_t_[attr] = aa_.t_a.at(attr);
  Element t_new(ctx_, 3);
  t_new.set_random();
  aa_.t_a[attr] = t_new;
  Element pk(ctx_, 0);
  pk.pow_zn(pp_.g, t_new);
  pp_.pk_attr[attr] = pk;
}

Element CryptoEngine::aa_refresh_attr_component(const Element& old_Eua, const std::string& attr) {
  // E_new = old_Eua ^{t_old / t_new}; ratio never leaves AA.
  auto it = last_revoked_old_t_.find(attr);
  if (it == last_revoked_old_t_.end()) {
    throw std::runtime_error("aa_refresh_attr_component: missing previous t_a for " + attr);
  }
  Element ratio(ctx_, 3);
  Element inv_new(ctx_, 3);
  inv_new.invert(aa_.t_a.at(attr));
  element_mul(ratio.raw(), it->second.raw(), inv_new.raw());
  Element out(ctx_, 0);
  out.pow_zn(old_Eua, ratio);
  return out;
}

void CryptoEngine::rm_refresh_xi() {
  Element xi_new(ctx_, 3);
  do {
    xi_new.set_random();
    bool ok = true;
    for (const auto& kv : rm_.s_i) {
      Element sum(ctx_, 3);
      element_add(sum.raw(), kv.second.raw(), xi_new.raw());
      if (element_is0(sum.raw())) {
        ok = false;
        break;
      }
    }
    if (ok) {
      break;
    }
  } while (true);
  rm_.xi = xi_new;
  for (auto& kv : rm_.s_i) {
    Element sum(ctx_, 3);
    element_add(sum.raw(), kv.second.raw(), rm_.xi.raw());
    Element pk(ctx_, 0);
    pk.pow_zn(pp_.g, sum);
    pp_.pk_role[kv.first] = pk;
    Element rs(ctx_, 3);
    rs.invert(sum);
    rm_.rs[kv.first] = rs;
  }
}

Element CryptoEngine::rm_reissue_rk(const std::string& role_id,
                                    const Element& D1,
                                    const std::string& user_id) {
  return rm_issue_rk(role_id, D1, user_id);
}

}  // namespace hierastream
