// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace tailcat {

// Blocking host TCP socket used at the boundary between Tailcat's userspace
// stack and ordinary localhost services. Network protocol state inside the
// tunnel remains in lwIP; these sockets are only for explicit CLI forwarding.
class HostTcpStream {
 public:
  ~HostTcpStream();
  HostTcpStream(const HostTcpStream&) = delete;
  HostTcpStream& operator=(const HostTcpStream&) = delete;
  HostTcpStream(HostTcpStream&&) noexcept;
  HostTcpStream& operator=(HostTcpStream&&) noexcept;

  static std::shared_ptr<HostTcpStream> connect(const std::string& host,
                                                 std::uint16_t port);

  // Blocks until bytes arrive, EOF, or an error. Empty means EOF.
  std::vector<std::uint8_t> read_some(std::size_t max_bytes = 16U * 1024U);
  void write_all(std::span<const std::uint8_t> data);
  void shutdown_write();
  void close() noexcept;
  bool open() const noexcept;

 private:
  struct Impl;
  explicit HostTcpStream(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
  friend class HostTcpListener;
};

class HostTcpListener {
 public:
  ~HostTcpListener();
  HostTcpListener(const HostTcpListener&) = delete;
  HostTcpListener& operator=(const HostTcpListener&) = delete;
  HostTcpListener(HostTcpListener&&) noexcept;
  HostTcpListener& operator=(HostTcpListener&&) noexcept;

  static HostTcpListener listen(const std::string& host, std::uint16_t port);
  std::shared_ptr<HostTcpStream> accept();
  std::uint16_t port() const noexcept;
  void close() noexcept;

 private:
  struct Impl;
  explicit HostTcpListener(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

}  // namespace tailcat
