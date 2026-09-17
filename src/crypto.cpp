#include "tailcat/crypto.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>

#if __has_include(<sodium.h>)
#include <sodium.h>
#else
extern "C" {
int sodium_init(void);
void randombytes_buf(void* const buf, const size_t size);
int crypto_box_keypair(unsigned char* pk, unsigned char* sk);
int crypto_box_easy(unsigned char* c, const unsigned char* m, unsigned long long mlen,
                    const unsigned char* n, const unsigned char* pk, const unsigned char* sk);
int crypto_box_open_easy(unsigned char* m, const unsigned char* c, unsigned long long clen,
                         const unsigned char* n, const unsigned char* pk, const unsigned char* sk);
int crypto_scalarmult_curve25519(unsigned char* q, const unsigned char* n, const unsigned char* p);
int crypto_generichash(unsigned char* out, size_t outlen, const unsigned char* in,
                       unsigned long long inlen, const unsigned char* key, size_t keylen);
int crypto_aead_xchacha20poly1305_ietf_encrypt(
    unsigned char* c, unsigned long long* clen_p, const unsigned char* m,
    unsigned long long mlen, const unsigned char* ad, unsigned long long adlen,
    const unsigned char* nsec, const unsigned char* npub, const unsigned char* k);
int crypto_aead_xchacha20poly1305_ietf_decrypt(
    unsigned char* m, unsigned long long* mlen_p, unsigned char* nsec,
    const unsigned char* c, unsigned long long clen, const unsigned char* ad,
    unsigned long long adlen, const unsigned char* npub, const unsigned char* k);
}
#endif

namespace tailcat {
namespace {
constexpr std::size_t kBoxNonce = 24;
constexpr std::size_t kBoxMac = 16;
constexpr std::size_t kAeadNonce = 24;
constexpr std::size_t kAeadTag = 16;
}

void crypto_init() {
  static const int initialized = sodium_init();
  if (initialized < 0) throw Error("libsodium initialization failed");
}

KeyPair make_keypair() {
  crypto_init();
  KeyPair kp;
  if (crypto_box_keypair(kp.public_key.data(), kp.private_key.data()) != 0)
    throw Error("crypto_box_keypair failed");
  return kp;
}

Key32 random_key32() {
  crypto_init();
  Key32 ret{};
  randombytes_buf(ret.data(), ret.size());
  return ret;
}

Nonce24 random_nonce24() {
  crypto_init();
  Nonce24 ret{};
  randombytes_buf(ret.data(), ret.size());
  return ret;
}

std::vector<std::uint8_t> nacl_box_seal(std::span<const std::uint8_t> plaintext,
                                        const Key32& peer_public,
                                        const Key32& private_key) {
  crypto_init();
  const auto nonce = random_nonce24();
  std::vector<std::uint8_t> out(kBoxNonce + plaintext.size() + kBoxMac);
  std::copy(nonce.begin(), nonce.end(), out.begin());
  if (crypto_box_easy(out.data() + kBoxNonce, plaintext.data(), plaintext.size(), nonce.data(),
                      peer_public.data(), private_key.data()) != 0) {
    throw Error("crypto_box_easy failed");
  }
  return out;
}

std::vector<std::uint8_t> nacl_box_open(std::span<const std::uint8_t> boxed,
                                        const Key32& peer_public,
                                        const Key32& private_key) {
  crypto_init();
  if (boxed.size() < kBoxNonce + kBoxMac) throw Error("short NaCl box");
  std::vector<std::uint8_t> out(boxed.size() - kBoxNonce - kBoxMac);
  if (crypto_box_open_easy(out.data(), boxed.data() + kBoxNonce, boxed.size() - kBoxNonce,
                           boxed.data(), peer_public.data(), private_key.data()) != 0) {
    throw Error("NaCl box authentication failed");
  }
  return out;
}

Key32 derive_session_key(const Key32& private_key,
                         const Key32& peer_public,
                         const Key32& preshared_key) {
  crypto_init();
  Key32 shared{};
  if (crypto_scalarmult_curve25519(shared.data(), private_key.data(), peer_public.data()) != 0)
    throw Error("X25519 key agreement failed");
  std::array<std::uint8_t, 32 + 32 + 15> material{};
  std::copy(shared.begin(), shared.end(), material.begin());
  std::copy(preshared_key.begin(), preshared_key.end(), material.begin() + 32);
  constexpr std::string_view label = "tailcat-cpp-v1";
  std::copy(label.begin(), label.end(), material.begin() + 64);
  Key32 out{};
  if (crypto_generichash(out.data(), out.size(), material.data(), material.size(), nullptr, 0) != 0)
    throw Error("session key derivation failed");
  return out;
}

std::vector<std::uint8_t> encrypt_packet(std::span<const std::uint8_t> plaintext,
                                         const Key32& session_key) {
  crypto_init();
  const auto nonce = random_nonce24();
  std::vector<std::uint8_t> out(kAeadNonce + plaintext.size() + kAeadTag);
  std::copy(nonce.begin(), nonce.end(), out.begin());
  unsigned long long clen = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
          out.data() + kAeadNonce, &clen, plaintext.data(), plaintext.size(), nullptr, 0,
          nullptr, nonce.data(), session_key.data()) != 0) {
    throw Error("XChaCha20-Poly1305 encryption failed");
  }
  out.resize(kAeadNonce + static_cast<std::size_t>(clen));
  return out;
}

std::vector<std::uint8_t> decrypt_packet(std::span<const std::uint8_t> ciphertext,
                                         const Key32& session_key) {
  crypto_init();
  if (ciphertext.size() < kAeadNonce + kAeadTag) throw Error("short encrypted packet");
  std::vector<std::uint8_t> out(ciphertext.size() - kAeadNonce - kAeadTag);
  unsigned long long mlen = 0;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          out.data(), &mlen, nullptr, ciphertext.data() + kAeadNonce,
          ciphertext.size() - kAeadNonce, nullptr, 0, ciphertext.data(),
          session_key.data()) != 0) {
    throw Error("encrypted packet authentication failed");
  }
  out.resize(static_cast<std::size_t>(mlen));
  return out;
}

std::string hex(std::span<const std::uint8_t> input) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(input.size() * 2);
  for (auto b : input) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 15]);
  }
  return out;
}

std::uint32_t read_be32(const std::uint8_t* p) {
  return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
         (std::uint32_t(p[2]) << 8) | p[3];
}
void append_be32(std::vector<std::uint8_t>& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 24));
  out.push_back(static_cast<std::uint8_t>(v >> 16));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}
std::uint16_t read_be16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((std::uint16_t(p[0]) << 8) | p[1]);
}
void append_be16(std::vector<std::uint8_t>& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}

}  // namespace tailcat
