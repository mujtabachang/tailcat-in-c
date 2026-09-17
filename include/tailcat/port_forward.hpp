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

struct ServedTcpMapping {
  std::uint16_t tailcat_port = 0;
  std::uint16_t host_port = 0;
};

// Exposes selected TCP ports on a TailcatServerDataPlane and proxies each
// accepted userspace TCP stream to a loopback/host TCP target. Host socket
// reads run outside the lwIP/DERP event loop so a quiet local service cannot
// stall relay processing.
class ServedTcpPorts {
 public:
  ServedTcpPorts(TailcatServerDataPlane& data_plane,
                 std::vector<std::uint16_t> ports,
                 std::string host = "127.0.0.1");
  ServedTcpPorts(TailcatServerDataPlane& data_plane,
                 std::vector<ServedTcpMapping> mappings,
                 std::string host = "127.0.0.1");
  ~ServedTcpPorts();
  ServedTcpPorts(const ServedTcpPorts&) = delete;
  ServedTcpPorts& operator=(const ServedTcpPorts&) = delete;

  void poll();
  std::size_t connection_count() const noexcept;
  const std::vector<std::uint16_t>& ports() const noexcept;
  const std::vector<ServedTcpMapping>& mappings() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tailcat
