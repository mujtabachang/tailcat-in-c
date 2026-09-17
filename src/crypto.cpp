#include "tailcat/crypto.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <mutex>
#include <stdexcept>
#include <string_view>

namespace tailcat {
namespace {

void clamp_curve25519(Key32& key) {
  key[0] &= 248;
  key[31] &= 127;
  key[31] |= 64;
}

void ensure_crypto() {
  static std::once_flag once;
  static int init_result = -1;
  std::call_once(once, [] { init_result = sodium_init(); });
  if (init_result < 0) throw std::runtime_error("libsodium initialization failed");
}

}  // namespace

void initialize_crypto() { ensure_crypto(); }

Key32 node_public_from_private(const Key32& private_key) {
  ensure_crypto();
  Key32 pub{};
  if (crypto_scalarmult_curve25519_base(pub.data(), private_key.data()) != 0) {
    throw std::runtime_error("failed to derive Curve25519 public key");
  }
  return pub;
}

NodeKeyPair generate_node_keypair() {
  ensure_crypto();
  NodeKeyPair pair;
  do {
    randombytes_buf(pair.private_key.data(), pair.private_key.size());
    clamp_curve25519(pair.private_key);
  } while (std::all_of(pair.private_key.begin(), pair.private_key.end(), [](auto b) { return b == 0; }));
  pair.public_key = node_public_from_private(pair.private_key);
  return pair;
}

Key32 derive_disco_private(const Key32& node_private_key) {
  ensure_crypto();
  constexpr std::string_view context = "github.com/tailscale/tailcat disco key v1";
  Key32 out{};
  crypto_auth_hmacsha256_state state{};
  crypto_auth_hmacsha256_init(&state, node_private_key.data(), node_private_key.size());
  crypto_auth_hmacsha256_update(
      &state,
      reinterpret_cast<const unsigned char*>(context.data()),
      static_cast<unsigned long long>(context.size()));
  crypto_auth_hmacsha256_final(&state, out.data());
  clamp_curve25519(out);
  return out;
}

Key32 derive_disco_public(const Key32& node_private_key) {
  return node_public_from_private(derive_disco_private(node_private_key));
}

Key32 generate_preshared_key() {
  ensure_crypto();
  Key32 psk{};
  do {
    randombytes_buf(psk.data(), psk.size());
  } while (std::all_of(psk.begin(), psk.end(), [](auto b) { return b == 0; }));
  return psk;
}

std::vector<std::uint8_t> nacl_box_seal(
    const Key32& sender_private,
    const Key32& recipient_public,
    std::span<const std::uint8_t> plaintext) {
  ensure_crypto();
  std::array<unsigned char, crypto_box_NONCEBYTES> nonce{};
  randombytes_buf(nonce.data(), nonce.size());
  std::vector<std::uint8_t> out(nonce.size() + crypto_box_MACBYTES + plaintext.size());
  std::copy(nonce.begin(), nonce.end(), out.begin());
  if (crypto_box_easy(
          out.data() + nonce.size(),
          plaintext.data(),
          static_cast<unsigned long long>(plaintext.size()),
          nonce.data(),
          recipient_public.data(),
          sender_private.data()) != 0) {
    throw std::runtime_error("NaCl box encryption failed");
  }
  return out;
}

std::optional<std::vector<std::uint8_t>> nacl_box_open(
    const Key32& recipient_private,
    const Key32& sender_public,
    std::span<const std::uint8_t> sealed) {
  ensure_crypto();
  if (sealed.size() < crypto_box_NONCEBYTES + crypto_box_MACBYTES) return std::nullopt;
  const auto ciphertext = sealed.subspan(crypto_box_NONCEBYTES);
  std::vector<std::uint8_t> clear(ciphertext.size() - crypto_box_MACBYTES);
  if (crypto_box_open_easy(
          clear.data(),
          ciphertext.data(),
          static_cast<unsigned long long>(ciphertext.size()),
          sealed.data(),
          sender_public.data(),
          recipient_private.data()) != 0) {
    return std::nullopt;
  }
  return clear;
}

}  // namespace tailcat
