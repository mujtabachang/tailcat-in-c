// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/protocol.hpp"

#include <vector>

namespace tailcat {

struct NodeKeyPair {
  Key32 private_key{};
  Key32 public_key{};
};

void initialize_crypto();
NodeKeyPair generate_node_key();
NodeKeyPair derive_disco_key(const Key32& node_private_key);
Key32 generate_secret_key();
Key32 node_public_from_private(const Key32& private_key);
std::vector<std::uint8_t> nacl_box_seal(const Key32& private_key, const Key32& peer_public,
                                        const std::vector<std::uint8_t>& plaintext);
std::vector<std::uint8_t> nacl_box_open(const Key32& private_key, const Key32& peer_public,
                                        const std::vector<std::uint8_t>& boxed);

}  // namespace tailcat
