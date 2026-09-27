#pragma once

#include <pbc/pbc.h>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace hierastream {

// Thin RAII wrapper around PBC pairing_t / element_t.
// Formal experiments must load an external parameter file (see crypto/params/).
// Do NOT claim a concrete security level until parameters are verified.
//
// NOTE: PBC's C API is not const-correct (element_t is element_s[1]).
// Const Element methods therefore use const_cast at the PBC boundary only.

class PairingContext {
 public:
  explicit PairingContext(const std::string& param_path);
  ~PairingContext();

  PairingContext(const PairingContext&) = delete;
  PairingContext& operator=(const PairingContext&) = delete;

  pairing_t& pairing() { return pairing_; }
  const pairing_t& pairing() const { return pairing_; }

  mpz_t& order() { return order_; }

 private:
  pairing_t pairing_{};
  mpz_t order_{};
};

class Element {
 public:
  Element() = default;
  Element(PairingContext& ctx, int element_type);
  ~Element();

  Element(const Element& other);
  Element& operator=(const Element& other);
  Element(Element&& other) noexcept;
  Element& operator=(Element&& other) noexcept;

  element_t& raw() { return e_; }
  element_t& raw() const { return const_cast<element_t&>(e_); }

  void set_random();
  void set_one();
  void set_zr_from_hash(const uint8_t* data, size_t len);
  void from_bytes(const std::vector<uint8_t>& bytes);
  std::vector<uint8_t> to_bytes() const;

  void pow_zn(const Element& base, const Element& exp);
  void mul(const Element& a, const Element& b);
  void add(const Element& a, const Element& b);
  void sub(const Element& a, const Element& b);
  void div(const Element& a, const Element& b);
  void invert(const Element& a);
  void neg(const Element& a);
  void pairing(const Element& a, const Element& b);
  bool equals(const Element& other) const;
  bool is_0() const;
  int element_type() const { return type_; }
  void set_si(long v);
  void set_mpz_str(const std::string& dec);

 private:
  void clear();
  PairingContext* ctx_ = nullptr;
  element_t e_{};
  bool init_ = false;
  int type_ = 0;
};

}  // namespace hierastream
