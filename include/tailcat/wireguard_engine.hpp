// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/crypto.hpp"
#include "tailcat/protocol.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace tailcat {

struct WireGuardPacketResult {
  std::vector<std::uint8_t> outbound;
  std::optional<std::vector<std::uint8_t>> plaintext_ip;
  bool session_established = false;
};

// One native WireGuard peer relationship. Tailcat's DERP layer determines the
// outer packet destination/source, so this engine only owns WireGuard's Noise
// handshake, preshared-key mixing, replay protection and transport encryption.
class WireGuardPeerEngine {
 public:
  WireGuardPeerEngine(NodeKeyPair local_identity, Key32 peer_public,
                      std::optional<Key32> preshared_key = std::nullopt);
  ~WireGuardPeerEngine();
  WireGuardPeerEngine(const WireGuardPeerEngine&) = delete;
  WireGuardPeerEngine& operator=(const WireGuardPeerEngine&) = delete;
  WireGuardPeerEngine(WireGuardPeerEngine&&) noexcept;
  WireGuardPeerEngine& operator=(WireGuardPeerEngine&&) noexcept;

  std::vector<std::uint8_t> create_handshake_initiation();
  WireGuardPacketResult handle_packet(std::span<const std::uint8_t> packet);
  std::vector<std::uint8_t> encrypt_ip_packet(std::span<const std::uint8_t> packet);

  bool session_established() const noexcept;
  const Key32& peer_public_key() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tailcat
