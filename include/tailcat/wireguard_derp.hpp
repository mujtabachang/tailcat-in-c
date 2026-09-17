// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/derp_transport.hpp"
#include "tailcat/wireguard_engine.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace tailcat {

// Carries a native WireGuard peer relationship over DERP packets. DERP only
// transports opaque WireGuard datagrams; WireGuard remains the end-to-end
// authenticated/encrypted data plane exactly as in upstream Tailcat.
class WireGuardDerpPeer {
 public:
  WireGuardDerpPeer(DerpTransport& transport, NodeKeyPair local_identity,
                    Key32 peer_public,
                    std::optional<Key32> preshared_key = std::nullopt);

  // Initiator-side handshake. Retries with a fresh initiation every five
  // seconds (WireGuard's REKEY_TIMEOUT) until the deadline expires.
  void connect(std::chrono::milliseconds timeout = std::chrono::seconds(10));

  // Process DERP control frames and WireGuard datagrams for up to timeout.
  // Returns one decrypted inner IP packet when available.
  std::optional<std::vector<std::uint8_t>> pump_for(
      std::chrono::milliseconds timeout);

  // Encrypt and transmit one complete IPv4/IPv6 packet to the peer over DERP.
  void send_ip_packet(std::span<const std::uint8_t> packet);

  bool session_established() const noexcept;
  const Key32& peer_public_key() const noexcept;

 private:
  bool receive_one_for(std::chrono::milliseconds timeout,
                       std::optional<std::vector<std::uint8_t>>& plaintext);

  DerpTransport& transport_;
  Key32 peer_public_{};
  WireGuardPeerEngine wireguard_;
};

}  // namespace tailcat
