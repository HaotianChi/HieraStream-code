#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "hierastream/aead_kdf.hpp"
#include "hierastream/crypto_engine.hpp"
#include "hierastream/pairing.hpp"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace py = pybind11;

namespace {

constexpr int kG = 0;
constexpr int kGT = 2;
constexpr int kZr = 3;

}  // namespace

PYBIND11_MODULE(hierastream_native, m) {
  m.doc() = "HieraStream C++/PBC cryptographic core (Section III)";

  m.attr("ELEM_G") = kG;
  m.attr("ELEM_GT") = kGT;
  m.attr("ELEM_ZR") = kZr;

  m.def("ping", []() { return std::string("hierastream_native"); });

  py::class_<hierastream::PairingContext, std::shared_ptr<hierastream::PairingContext>>(
      m, "PairingContext")
      .def(py::init<const std::string&>(), py::arg("param_path"));

  py::class_<hierastream::Element>(m, "Element")
      .def(py::init([](std::shared_ptr<hierastream::PairingContext> ctx, int ty) {
             return hierastream::Element(*ctx, ty);
           }),
           py::arg("ctx"), py::arg("element_type"), py::keep_alive<1, 2>())
      .def("set_random", &hierastream::Element::set_random)
      .def("set_one", &hierastream::Element::set_one)
      .def("set_si", &hierastream::Element::set_si)
      .def("set_mpz_str", &hierastream::Element::set_mpz_str)
      .def("set_zr_from_hash",
           [](hierastream::Element& self, const py::bytes& data) {
             std::string s = data;
             self.set_zr_from_hash(reinterpret_cast<const uint8_t*>(s.data()), s.size());
           })
      .def("to_bytes",
           [](const hierastream::Element& self) {
             auto v = self.to_bytes();
             return py::bytes(reinterpret_cast<const char*>(v.data()), v.size());
           })
      .def("from_bytes",
           [](hierastream::Element& self, const py::bytes& data) {
             std::string s = data;
             self.from_bytes(std::vector<uint8_t>(s.begin(), s.end()));
           })
      .def("pow_zn", &hierastream::Element::pow_zn)
      .def("mul", &hierastream::Element::mul)
      .def("add", &hierastream::Element::add)
      .def("sub", &hierastream::Element::sub)
      .def("div", &hierastream::Element::div)
      .def("invert", &hierastream::Element::invert)
      .def("neg", &hierastream::Element::neg)
      .def("pairing", &hierastream::Element::pairing)
      .def("equals", &hierastream::Element::equals)
      .def("is_0", &hierastream::Element::is_0)
      .def("element_type", &hierastream::Element::element_type);

  m.def(
      "pairing_smoke",
      [](const std::string& param_path) {
        hierastream::PairingContext ctx(param_path);
        hierastream::Element g(ctx, kG);
        hierastream::Element a(ctx, kZr);
        g.set_random();
        a.set_random();
        hierastream::Element ga(ctx, kG);
        ga.pow_zn(g, a);
        hierastream::Element gt(ctx, kGT);
        gt.pairing(ga, g);
        auto v = gt.to_bytes();
        return py::bytes(reinterpret_cast<const char*>(v.data()), v.size());
      },
      py::arg("param_path"));

  m.def(
      "aes_gcm_roundtrip",
      [](const std::vector<uint8_t>& key, const std::vector<uint8_t>& pt) {
        auto blob = hierastream::aes_gcm_encrypt(key, pt);
        return hierastream::aes_gcm_decrypt(key, blob);
      },
      py::arg("key32"), py::arg("plaintext"));

  m.def(
      "hkdf_sha256",
      [](const std::vector<uint8_t>& ikm, const std::vector<uint8_t>& info, size_t n) {
        return hierastream::hkdf_sha256(ikm, info, n);
      },
      py::arg("ikm"), py::arg("info"), py::arg("length"));

  m.def(
      "kdf_domain_xor",
      [](const std::vector<uint8_t>& za, const std::vector<uint8_t>& zr) {
        auto ka = hierastream::kdf_gt_bytes(za, "HieraStream-Attribute-v1");
        auto kr = hierastream::kdf_gt_bytes(zr, "HieraStream-Role-v1");
        return hierastream::xor_bytes(ka, kr);
      },
      py::arg("za_canonical"), py::arg("zr_canonical"));

  m.def(
      "engine_setup_smoke",
      [](const std::string& param_path) {
        hierastream::CryptoEngine eng(param_path);
        eng.ca_setup();
        eng.aa_setup({"doctor", "nurse"});
        return true;
      },
      py::arg("param_path"));

  // Section III semantic path on PBC (attr recover + dual-share KDF + revoke/reissue).
  m.def(
      "engine_section_iii_roundtrip",
      [](const std::string& param_path, const std::string& plaintext) {
        using hierastream::AccessTreeNode;
        using hierastream::CryptoEngine;

        CryptoEngine eng(param_path);
        eng.ca_setup();
        eng.aa_setup({"doctor", "cardiology", "nurse"});
        eng.role_setup(
            {{"ChiefMedicalOfficer", {"ChiefMedicalOfficer"}},
             {"AttendingPhysician", {"ChiefMedicalOfficer", "AttendingPhysician"}},
             {"Nurse", {"Nurse"}}},
            {"ChiefMedicalOfficer", "AttendingPhysician", "Nurse"});

        auto attr = eng.aa_keygen_user({"doctor", "cardiology"});
        auto role = eng.ca_role_user_material("alice");
        auto rk = eng.rm_issue_rk("AttendingPhysician", role.D1, "alice");
        role.RK["AttendingPhysician"] = rk;

        auto ZA = eng.sample_gt();
        auto ZR = eng.sample_gt();
        auto partial = eng.gateway_partial_attr_encrypt(ZA);

        AccessTreeNode root;
        root.kind = AccessTreeNode::Kind::Internal;
        root.threshold = 2;
        AccessTreeNode leaf_d;
        leaf_d.kind = AccessTreeNode::Kind::Leaf;
        leaf_d.attr = "doctor";
        leaf_d.index = 1;
        AccessTreeNode leaf_c;
        leaf_c.kind = AccessTreeNode::Kind::Leaf;
        leaf_c.attr = "cardiology";
        leaf_c.index = 2;
        root.children = {leaf_d, leaf_c};

        auto ct = eng.outsource_policy_encrypt(partial, root);
        auto Bj = eng.outsource_attr_transform(ct, attr);
        if (!Bj) {
          throw std::runtime_error("attr transform failed");
        }
        auto ZA2 = eng.user_recover_ZA(ct, *Bj, attr.usk1);
        if (!ZA2.equals(ZA)) {
          throw std::runtime_error("ZA mismatch");
        }

        // Role encrypt + outsource transform + recover
        auto H = std::vector<std::string>{"ChiefMedicalOfficer", "AttendingPhysician"};
        auto env = eng.gateway_role_encrypt(ZR, "AttendingPhysician", H);
        auto omega = eng.sample_zr();
        hierastream::Element TR = rk;
        TR.pow_zn(rk, omega);

        auto Gamma = std::vector<std::string>{};  // Γ(rx,ri)=∅ when rx==ri
        auto pq = eng.outsource_role_transform(env, TR, role.D0, Gamma);
        auto ZR2 = eng.user_recover_ZR(env, pq.first, pq.second, omega, role.rho_u);
        if (!ZR2.equals(ZR)) {
          throw std::runtime_error("ZR mismatch");
        }

        auto za_b = ZA.to_bytes();
        auto zr_b = ZR.to_bytes();
        auto key = hierastream::xor_bytes(
            hierastream::kdf_gt_bytes(za_b, "HieraStream-Attribute-v1"),
            hierastream::kdf_gt_bytes(zr_b, "HieraStream-Role-v1"));
        std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());
        auto blob = hierastream::aes_gcm_encrypt(key, pt);
        auto out = hierastream::aes_gcm_decrypt(key, blob);
        if (out != pt) {
          throw std::runtime_error("AEAD roundtrip failed");
        }

        // Historical access: keep old E_ua; revoke updates AA secret; old CT still uses old keys
        auto old_eua = attr.E_ua["doctor"];
        eng.aa_revoke_attribute("doctor");
        auto refreshed = eng.aa_refresh_attr_component(old_eua, "doctor");
        if (refreshed.equals(old_eua)) {
          throw std::runtime_error("refresh must change E_ua");
        }

        eng.rm_refresh_xi();
        auto rk2 = eng.rm_reissue_rk("AttendingPhysician", role.D1, "alice");
        if (rk2.equals(rk)) {
          throw std::runtime_error("reissue must change RK");
        }

        py::dict result;
        result["ok"] = true;
        result["za_len"] = static_cast<int>(za_b.size());
        result["zr_len"] = static_cast<int>(zr_b.size());
        result["key_len"] = static_cast<int>(key.size());
        result["pt"] = plaintext;
        return result;
      },
      py::arg("param_path"), py::arg("plaintext") = "pbc-section-iii");
}
