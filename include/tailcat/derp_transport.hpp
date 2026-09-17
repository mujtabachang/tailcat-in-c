// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/derp.hpp"
#include "tailcat/protocol.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

namespace tailcat {

// Packet-oriented interface to a DERP relay. Implementations own the DERP
// connection and framing; users exchange authenticated source/destination node
// keys and opaque packet bytes exactly as Tailscale's DERP protocol does.
class DerpTransport {
 public:
  virtual ~DerpTransport() = default;

  virtual void send_packet(const Key32& destination,
                           const std::vector<std::uint8_t>& packet) = 0;
  virtual void send_pong(const std::array<std::uint8_t, 8>& value) = 0;
  virtual std::optional<DerpFrame> receive_for(std::chrono::milliseconds timeout) = 0;
};

}  // namespace tailcat
