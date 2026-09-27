#include "hierastream/aead_kdf.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <stdexcept>

namespace hierastream {

namespace {

void require_ok(int rc, const char* what) {
  if (rc != 1) {
    throw std::runtime_error(std::string("OpenSSL failure: ") + what);
  }
}

}  // namespace

std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                 const std::vector<uint8_t>& info,
                                 size_t length,
                                 const std::vector<uint8_t>& salt) {
  std::vector<uint8_t> out(length);
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!pctx) {
    throw std::runtime_error("EVP_PKEY_CTX_new_id HKDF");
  }
  require_ok(EVP_PKEY_derive_init(pctx), "derive_init");
  require_ok(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()), "set_hkdf_md");
  if (!salt.empty()) {
    require_ok(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size())),
               "set_salt");
  } else {
    require_ok(EVP_PKEY_CTX_set1_hkdf_salt(pctx, reinterpret_cast<const unsigned char*>(""), 0),
               "set_empty_salt");
  }
  require_ok(EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), static_cast<int>(ikm.size())), "set_key");
  require_ok(EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), static_cast<int>(info.size())),
             "set_info");
  size_t outlen = length;
  require_ok(EVP_PKEY_derive(pctx, out.data(), &outlen), "derive");
  EVP_PKEY_CTX_free(pctx);
  out.resize(outlen);
  return out;
}

std::vector<uint8_t> kdf_gt_bytes(const std::vector<uint8_t>& gt_canonical,
                                 const std::string& domain_tag) {
  std::vector<uint8_t> info(domain_tag.begin(), domain_tag.end());
  return hkdf_sha256(gt_canonical, info, 32);
}

std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
  if (a.size() != b.size()) {
    throw std::runtime_error("xor_bytes length mismatch");
  }
  std::vector<uint8_t> out(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    out[i] = static_cast<uint8_t>(a[i] ^ b[i]);
  }
  return out;
}

std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key32,
                                     const std::vector<uint8_t>& plaintext,
                                     const std::vector<uint8_t>& aad) {
  if (key32.size() != 32) {
    throw std::runtime_error("AES-256-GCM requires 32-byte key");
  }
  std::vector<uint8_t> nonce(12);
  if (RAND_bytes(nonce.data(), 12) != 1) {
    throw std::runtime_error("RAND_bytes");
  }
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new");
  }
  require_ok(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "enc_init");
  require_ok(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr), "set_ivlen");
  require_ok(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce.data()), "enc_key");
  int len = 0;
  if (!aad.empty()) {
    require_ok(EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())),
               "aad");
  }
  std::vector<uint8_t> ct(plaintext.size());
  require_ok(EVP_EncryptUpdate(ctx, ct.data(), &len, plaintext.data(),
                               static_cast<int>(plaintext.size())),
             "enc_update");
  int ct_len = len;
  require_ok(EVP_EncryptFinal_ex(ctx, ct.data() + len, &len), "enc_final");
  ct_len += len;
  ct.resize(static_cast<size_t>(ct_len));
  std::vector<uint8_t> tag(16);
  require_ok(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()), "get_tag");
  EVP_CIPHER_CTX_free(ctx);
  std::vector<uint8_t> out;
  out.reserve(12 + ct.size() + 16);
  out.insert(out.end(), nonce.begin(), nonce.end());
  out.insert(out.end(), ct.begin(), ct.end());
  out.insert(out.end(), tag.begin(), tag.end());
  return out;
}

std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& key32,
                                     const std::vector<uint8_t>& blob,
                                     const std::vector<uint8_t>& aad) {
  if (key32.size() != 32 || blob.size() < 12 + 16) {
    throw std::runtime_error("AES-GCM decrypt input invalid");
  }
  const uint8_t* nonce = blob.data();
  const uint8_t* tag = blob.data() + blob.size() - 16;
  const uint8_t* ct = blob.data() + 12;
  const int ct_len = static_cast<int>(blob.size() - 12 - 16);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  require_ok(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "dec_init");
  require_ok(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr), "set_ivlen");
  require_ok(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce), "dec_key");
  int len = 0;
  if (!aad.empty()) {
    require_ok(EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())),
               "aad");
  }
  std::vector<uint8_t> pt(static_cast<size_t>(ct_len));
  require_ok(EVP_DecryptUpdate(ctx, pt.data(), &len, ct, ct_len), "dec_update");
  int pt_len = len;
  require_ok(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)),
             "set_tag");
  if (EVP_DecryptFinal_ex(ctx, pt.data() + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("AES-GCM authentication failed");
  }
  pt_len += len;
  EVP_CIPHER_CTX_free(ctx);
  pt.resize(static_cast<size_t>(pt_len));
  return pt;
}

}  // namespace hierastream
