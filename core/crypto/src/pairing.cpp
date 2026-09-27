#include "hierastream/pairing.hpp"

#include <fstream>
#include <sstream>

namespace hierastream {

namespace {
std::string read_file(const std::string& path) {
  std::ifstream in(path);
  if (!in) {
    throw std::runtime_error("failed to open pairing param file: " + path);
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}
}  // namespace

PairingContext::PairingContext(const std::string& param_path) {
  const std::string param = read_file(param_path);
  pairing_init_set_buf(pairing_, param.data(), static_cast<int>(param.size()));
  if (!pairing_is_symmetric(pairing_)) {
    throw std::runtime_error(
        "pairing parameters are not symmetric; select a Type-A (or equivalent) file");
  }
  mpz_init(order_);
  mpz_set(order_, pairing_->r);
}

PairingContext::~PairingContext() {
  mpz_clear(order_);
  pairing_clear(pairing_);
}

Element::Element(PairingContext& ctx, int element_type) : ctx_(&ctx), type_(element_type) {
  element_init(e_, element_type == 0   ? ctx.pairing()->G1
                   : element_type == 1 ? ctx.pairing()->G2
                   : element_type == 2 ? ctx.pairing()->GT
                                       : ctx.pairing()->Zr);
  init_ = true;
}

Element::~Element() { clear(); }

void Element::clear() {
  if (init_) {
    element_clear(e_);
    init_ = false;
  }
}

Element::Element(const Element& other) : ctx_(other.ctx_), type_(other.type_) {
  if (!other.init_) {
    return;
  }
  element_init_same_as(e_, other.raw());
  element_set(e_, other.raw());
  init_ = true;
}

Element& Element::operator=(const Element& other) {
  if (this == &other) {
    return *this;
  }
  clear();
  ctx_ = other.ctx_;
  type_ = other.type_;
  if (other.init_) {
    element_init_same_as(e_, other.raw());
    element_set(e_, other.raw());
    init_ = true;
  }
  return *this;
}

Element::Element(Element&& other) noexcept : ctx_(other.ctx_), init_(false), type_(other.type_) {
  if (other.init_) {
    element_init_same_as(e_, other.raw());
    element_set(e_, other.raw());
    init_ = true;
    other.clear();
  }
}

Element& Element::operator=(Element&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  clear();
  ctx_ = other.ctx_;
  type_ = other.type_;
  if (other.init_) {
    element_init_same_as(e_, other.raw());
    element_set(e_, other.raw());
    init_ = true;
    other.clear();
  }
  return *this;
}

void Element::set_random() { element_random(e_); }

void Element::set_one() { element_set1(e_); }

void Element::set_zr_from_hash(const uint8_t* data, size_t len) {
  element_from_hash(e_, const_cast<uint8_t*>(data), static_cast<int>(len));
}

void Element::from_bytes(const std::vector<uint8_t>& bytes) {
  if (element_from_bytes(e_, const_cast<uint8_t*>(bytes.data())) <= 0) {
    throw std::runtime_error("element_from_bytes failed");
  }
}

std::vector<uint8_t> Element::to_bytes() const {
  const int n = element_length_in_bytes(raw());
  std::vector<uint8_t> out(static_cast<size_t>(n));
  element_to_bytes(out.data(), raw());
  return out;
}

void Element::pow_zn(const Element& base, const Element& exp) {
  element_pow_zn(e_, base.raw(), exp.raw());
}

void Element::mul(const Element& a, const Element& b) { element_mul(e_, a.raw(), b.raw()); }

void Element::add(const Element& a, const Element& b) { element_add(e_, a.raw(), b.raw()); }

void Element::sub(const Element& a, const Element& b) { element_sub(e_, a.raw(), b.raw()); }

void Element::div(const Element& a, const Element& b) { element_div(e_, a.raw(), b.raw()); }

void Element::invert(const Element& a) { element_invert(e_, a.raw()); }

void Element::neg(const Element& a) { element_neg(e_, a.raw()); }

void Element::pairing(const Element& a, const Element& b) {
  element_pairing(e_, a.raw(), b.raw());
}

bool Element::equals(const Element& other) const {
  return element_cmp(raw(), other.raw()) == 0;
}

bool Element::is_0() const { return element_is0(raw()) != 0; }

void Element::set_si(long v) { element_set_si(e_, v); }

void Element::set_mpz_str(const std::string& dec) {
  mpz_t z;
  mpz_init(z);
  if (mpz_set_str(z, dec.c_str(), 10) != 0) {
    mpz_clear(z);
    throw std::runtime_error("invalid mpz decimal string");
  }
  element_set_mpz(e_, z);
  mpz_clear(z);
}

}  // namespace hierastream
