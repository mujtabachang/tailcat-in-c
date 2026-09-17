// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/crypto.hpp"

#include <sodium.h>

#include <algorithm>
#include <stdexcept>

namespace tailcat {

void initialize_crypto() {
  if (sodium_init() < 0) throw std::runtime_error("libsodium initialization failed");
}

Key32 node_public_from_private(const Key32& private_key) {
  Key32 out{};
  if (crypto_scalarmult_curve25519_base(out.data(), private_key.data()) != 0) {
    throw std::runtime_error("failed to derive X25519 public key");
  }
  return out;
}

NodeKeyPair generate_node_key() {
  NodeKeyPair out;
  randombytes_buf(out.private_key.data(), out.private_key.size());
  // Match tailscale/types/key.NewNode: clamp before using the key for both
  // WireGuard and DERP NaCl box operations.
  out.private_key[0] &= 248U;
  out.private_key[31] &= 127U;
  out.private_key[31] |= 64U;
  out.public_key = node_public_from_private(out.private_key);
  return out;
}

Key32 generate_secret_key() {
  Key32 out{};
  do {
    randombytes_buf(out.data(), out.size());
  } while (std::all_of(out.begin(), out.end(), [](std::uint8_t b) { return b == 0; }));
  return out;
}

std::vector<std::uint8_t> nacl_box_seal(const Key32& private_key, const Key32& peer_public,
                                        const std::vector<std::uint8_t>& plaintext) {
  std::array<unsigned char, crypto_box_NONCEBYTES> nonce{};
  randombytes_buf(nonce.data(), nonce.size());
  std::vector<std::uint8_t> out(nonce.size() + crypto_box_MACBYTES + plaintext.size());
  std::copy(nonce.begin(), nonce.end(), out.begin());
  if (crypto_box_easy(out.data() + nonce.size(), plaintext.data(),
                      static_cast<unsigned long long>(plaintext.size()), nonce.data(),
                      peer_public.data(), private_key.data()) != 0) {
    throw std::runtime_error("NaCl box seal failed");
  }
  return out;
}

std::vector<std::uint8_t> nacl_box_open(const Key32& private_key, const Key32& peer_public,
                                        const std::vector<std::uint8_t>& boxed) {
  if (boxed.size() < crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
    throw std::runtime_error("short NaCl box");
  }
  const auto* nonce = boxed.data();
  const auto* ciphertext = boxed.data() + crypto_box_NONCEBYTES;
  const auto ciphertext_size = boxed.size() - crypto_box_NONCEBYTES;
  std::vector<std::uint8_t> out(ciphertext_size - crypto_box_MACBYTES);
  if (crypto_box_open_easy(out.data(), ciphertext,
                           static_cast<unsigned long long>(ciphertext_size), nonce,
                           peer_public.data(), private_key.data()) != 0) {
    throw std::runtime_error("NaCl box authentication failed");
  }
  return out;
}

}  // namespace tailcat
