// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace tailcat {

struct SocksListenAddress {
  std::string host;
  std::uint16_t port = 0;
};

// Matches upstream's --listen normalization: a bare port binds localhost, a
// bare address gets an OS-assigned port, and [IPv6]:port is accepted.
SocksListenAddress parse_socks_listen_address(std::string_view value);

// Runs a SOCKS5 proxy whose TCP CONNECT requests for server.tailcat are carried
// over one Tailcat client session. Additional target classes (direct tc... and
// exit-node destinations) are layered on the same parser/connection engine.
int run_socks_command(const std::vector<std::string>& args, bool verbose,
                      std::string_view key_name = {});

}  // namespace tailcat
