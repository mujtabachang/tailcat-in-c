#pragma once

#include "tailcat/common.hpp"

#include <span>
#include <vector>

namespace tailcat {

struct KeyPair {
  Key32 public_key{};
  Key32 private_key{};
};

void crypto_init();
KeyPair make_keypair();
Key32 random_key32();
Nonce24 random_nonce24();

std::vector<std::uint8_t> nacl_box_seal(
    std::span<const std::uint8_t> plaintext,
    const Key32& peer_public,
    const Key32& private_key);

std::vector<std::uint8_t> nacl_box_open(
    std::span<const std::uint8_t> boxed,
    const Key32& peer_public,
    const Key32& private_key);

Key32 derive_session_key(const Key32& private_key,
                         const Key32& peer_public,
                         const Key32& preshared_key);

std::vector<std::uint8_t> encrypt_packet(
    std::span<const std::uint8_t> plaintext,
    const Key32& session_key);

std::vector<std::uint8_t> decrypt_packet(
    std::span<const std::uint8_t> ciphertext,
    const Key32& session_key);

}  // namespace tailcat
