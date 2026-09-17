// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/data_plane.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tailcat {

struct TcpForwardMapping {
  std::uint16_t local_port = 0;
  std::uint16_t remote_port = 0;
};

// Listens on ordinary host TCP sockets and sends each accepted stream through
// one already-connected Tailcat client data plane. Accept/read operations are
// kept off the single-threaded lwIP event loop.
class LocalTcpForwarder {
 public:
  LocalTcpForwarder(TailcatClientDataPlane& data_plane,
                    std::vector<TcpForwardMapping> mappings,
                    std::string bind_address = "127.0.0.1");
  ~LocalTcpForwarder();
  LocalTcpForwarder(const LocalTcpForwarder&) = delete;
  LocalTcpForwarder& operator=(const LocalTcpForwarder&) = delete;

  void poll();
  std::size_t connection_count() const noexcept;
  const std::vector<TcpForwardMapping>& mappings() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tailcat
