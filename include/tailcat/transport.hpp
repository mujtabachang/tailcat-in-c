// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace tailcat {

struct TcpEndpoint {
  std::string host;
  std::uint16_t port = 0;
};

TcpEndpoint parse_tcp_endpoint(std::string_view value);
std::string format_tcp_endpoint(const TcpEndpoint& endpoint);
int run_tcp_listener(std::string_view bind_host, std::uint16_t port);
int run_tcp_client(const TcpEndpoint& endpoint);

}  // namespace tailcat
