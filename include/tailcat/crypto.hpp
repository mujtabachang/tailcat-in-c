#pragma once

#include "tailcat/protocol.hpp"

#include <optional>
#include <span>
#include <vector>

namespace tailcat {

struct NodeKeyPair {
  Key32 private_key{};
  Key32 public_key{};
};

void initialize_crypto();
NodeKeyPair generate_node_keypair();
Key32 node_public_from_private(const Key32& private_key);
Key32 derive_disco_private(const Key32& node_private_key);
Key32 derive_disco_public(const Key32& node_private_key);
Key32 generate_preshared_key();

std::vector<std::uint8_t> nacl_box_seal(
    const Key32& sender_private,
    const Key32& recipient_public,
    std::span<const std::uint8_t> plaintext);

std::optional<std::vector<std::uint8_t>> nacl_box_open(
    const Key32& recipient_private,
    const Key32& sender_public,
    std::span<const std::uint8_t> sealed);

}  // namespace tailcat
