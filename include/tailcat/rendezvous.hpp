// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/derp_transport.hpp"
#include "tailcat/protocol.hpp"

#include <chrono>
#include <functional>
#include <optional>
#include <string>

namespace tailcat {

struct RendezvousPeer {
  Key32 node_public{};
  Key32 disco_public{};
};

// Perform Tailcat's client-side MEOW/MEOWED rendezvous over DERP. MEOW is
// retransmitted once per second because DERP packet delivery is best-effort.
// Returns the DERP round-trip latency once a MEOWED packet from server_public
// is received. Throws on timeout.
std::chrono::milliseconds rendezvous_client(
    DerpTransport& transport, const NodeKeyPair& node_identity,
    const Key32& disco_public, const Key32& server_public,
    std::chrono::milliseconds timeout = std::chrono::seconds(10));

// Wait for one valid client MEOW, optionally applying an allow predicate. The
// authenticated DERP source key is the peer identity, matching upstream
// Tailcat; the MEOW payload supplies the peer's separate disco public key.
// Accepted peers are acknowledged with MEOWED before being returned.
std::optional<RendezvousPeer> rendezvous_server_once(
    DerpTransport& transport, std::chrono::milliseconds timeout,
    const std::function<bool(const Key32&)>& allow = {});

}  // namespace tailcat
