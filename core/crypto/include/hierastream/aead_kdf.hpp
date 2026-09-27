#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hierastream {

// Portable AEAD + KDF helpers (OpenSSL). Big-endian integer helpers included.
// Domain separation tags match the journal prototype convention.

std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                 const std::vector<uint8_t>& info,
                                 size_t length,
                                 const std::vector<uint8_t>& salt = {});

std::vector<uint8_t> kdf_gt_bytes(const std::vector<uint8_t>& gt_canonical,
                                 const std::string& domain_tag);

std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// AES-256-GCM: output = 12-byte nonce || ciphertext||tag
std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key32,
                                     const std::vector<uint8_t>& plaintext,
                                     const std::vector<uint8_t>& aad = {});

std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& key32,
                                     const std::vector<uint8_t>& blob,
                                     const std::vector<uint8_t>& aad = {});

// Explicit big-endian encoding (architecture-independent).
inline void store_u64_be(uint64_t v, uint8_t out[8]) {
  for (int i = 7; i >= 0; --i) {
    out[i] = static_cast<uint8_t>(v & 0xff);
    v >>= 8;
  }
}

}  // namespace hierastream
