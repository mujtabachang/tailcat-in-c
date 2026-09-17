// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/protocol.hpp"

#include <array>
#include <cstdint>

namespace tailcat {

using Ip6Address = std::array<std::uint8_t, 16>;

// Derive the same IPv6 address that upstream Tailcat assigns to a node key:
// fd7a:115c:a1e0::/48 followed by the first 80 bits of the node public key.
Ip6Address tailcat_ip_for_node(const Key32& node_public) noexcept;

}  // namespace tailcat
