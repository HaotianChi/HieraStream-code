#pragma once

#include "hierastream/pairing.hpp"

#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace hierastream {

// Cryptographic construction corresponding to manuscript Section III.
// Comments cite equation numbers from the frozen journal draft.

struct PublicParams {
  Element g;   // generator of G
  Element Y;   // e(g,g)^alpha   Eq.(2)
  Element V;   // e(g,g)^delta   Eq.(2)
  Element h;   // g^beta         Eq.(3)
  Element W;   // g^delta        (provisioned to RM; also needed publicly for role ops)
  // Attribute public keys PK_a^(nu) = g^{t_a}
  std::map<std::string, Element> pk_attr;
  // Role public keys PK_ri^(nu) = g^{s_i + xi}
  std::map<std::string, Element> pk_role;
  // AR_i = g^{h_i}             Eq.(5)
  std::map<std::string, Element> ar;
};

struct CASecrets {
  Element alpha;
  Element delta;
  Element A;  // g^alpha
  Element F;  // g^{1/beta} received from AA
  std::map<std::string, Element> h_i;  // role path scalars
  std::map<std::string, Element> s_i;  // sum of h along A(r_i)
};

struct AASecrets {
  Element beta;
  Element A;  // from CA
  std::map<std::string, Element> t_a;  // current version secrets
};

struct RMSecrets {
  Element W;
  Element xi;  // current offset; xi_0 = 0
  std::map<std::string, Element> s_i;
  std::map<std::string, Element> rs;  // (s_i + xi)^{-1}
};

struct UserAttrKeys {
  Element usk1;                           // U_sk,1  (USER ONLY)
  Element E;
  Element E1;
  std::map<std::string, Element> E_ua;    // E_{u,a}^{(nu)}
  Element r_u;
  Element mu_u;
};

struct UserRoleMaterial {
  Element rho_u;  // USER ONLY
  Element D0;     // outsourcing
  Element D1;     // RM
  std::map<std::string, Element> RK;  // RK_{r_i,u}^{(nu)}
};

struct AccessTreeNode {
  enum class Kind { Leaf, Internal };
  Kind kind = Kind::Leaf;
  std::string attr;          // leaf
  int threshold = 1;         // k-of-n
  int index = 1;             // child index under parent
  std::vector<AccessTreeNode> children;
};

struct PartialAttrCT {
  Element C_tilde;   // ~C_j = Z^A * Y^{s1}
  Element C_prime;   // C'_j = g^{s1}
  Element C_dprime;  // C''_j = h^{s1}
  Element s1;
  Element ZA;
};

struct AttrCT {
  AccessTreeNode tree;
  Element C_tilde;
  Element C_prime;
  Element C_tilde_prime;   // g^{s1+s'}
  Element C_tilde_dprime;  // h^{s1+s'}
  std::map<std::string, Element> C_a;  // leaf components keyed by leaf-id/attr
  // leaf_id -> (attr, qx(0))
  std::map<std::string, std::pair<std::string, Element>> leaf_shares;
};

struct RoleEnvelope {
  std::string target_role;
  Element C1;
  Element C2;
  std::map<std::string, Element> C3;  // keyed by role id in H(ri)
  Element Ci;
};

class CryptoEngine {
 public:
  explicit CryptoEngine(const std::string& param_path);

  // System setup — Eqs.(2)-(6)
  void ca_setup();
  void aa_setup(const std::vector<std::string>& universe);
  void role_setup(const std::map<std::string, std::vector<std::string>>& auth_paths,
                  const std::vector<std::string>& role_order);

  const PublicParams& public_params() const { return pp_; }
  CASecrets& ca_secrets() { return ca_; }
  AASecrets& aa_secrets() { return aa_; }
  RMSecrets& rm_secrets() { return rm_; }

  // User provisioning — Eqs.(7)-(9)
  UserAttrKeys aa_keygen_user(const std::vector<std::string>& attrs);
  UserRoleMaterial ca_role_user_material(const std::string& user_id);
  Element rm_issue_rk(const std::string& role_id, const Element& D1, const std::string& user_id);

  // Dual-layer Z sampling helpers
  Element sample_gt();
  Element sample_zr();
  Element g_pow(const Element& exp);

  // Attribute encryption — Eqs.(13)-(16)
  PartialAttrCT gateway_partial_attr_encrypt(const Element& ZA);
  AttrCT outsource_policy_encrypt(const PartialAttrCT& partial, const AccessTreeNode& tree);

  // Attribute decryption — Eqs.(24)-(28)
  std::optional<Element> outsource_attr_transform(const AttrCT& ct, const UserAttrKeys& keys);
  Element user_recover_ZA(const AttrCT& ct, const Element& Bj, const Element& usk1);

  // Role encryption — Eqs.(19)-(21)
  RoleEnvelope gateway_role_encrypt(const Element& ZR,
                                    const std::string& target_role,
                                    const std::vector<std::string>& H_ri);

  // Role decryption — Eqs.(29)-(34)
  std::pair<Element, Element> outsource_role_transform(const RoleEnvelope& env,
                                                       const Element& TR,
                                                       const Element& D0,
                                                       const std::vector<std::string>& Gamma);
  Element user_recover_ZR(const RoleEnvelope& env,
                          const Element& P,
                          const Element& Q,
                          const Element& omega,
                          const Element& rho);

  // Attribute revocation — Eqs.(37)-(39)
  // Returns refreshed E_ua for non-revoked holders. NEVER exposes update ratio.
  Element aa_refresh_attr_component(const Element& old_Eua, const std::string& attr);
  void aa_revoke_attribute(const std::string& attr);

  // Role reassignment — Eq.(40)
  void rm_refresh_xi();
  Element rm_reissue_rk(const std::string& role_id, const Element& D1, const std::string& user_id);

  Element hash_to_zr(const std::string& s);

 private:
  void assign_polynomials(AccessTreeNode& node,
                          const Element& q0,
                          AttrCT& out,
                          const std::string& path_id);

  PairingContext ctx_;
  PublicParams pp_;
  CASecrets ca_;
  AASecrets aa_;
  RMSecrets rm_;
  bool ca_ready_ = false;
  bool aa_ready_ = false;
  bool roles_ready_ = false;
  std::map<std::string, Element> last_revoked_old_t_;
};

}  // namespace hierastream
