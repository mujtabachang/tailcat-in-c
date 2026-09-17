// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/ip.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace tailcat {

class LwipTcpStream {
 public:
  struct Impl;

  ~LwipTcpStream();
  LwipTcpStream(const LwipTcpStream&) = delete;
  LwipTcpStream& operator=(const LwipTcpStream&) = delete;

  bool connected() const noexcept;
  bool eof() const noexcept;
  bool failed() const noexcept;
  const std::string& error() const noexcept;
  std::size_t buffered() const noexcept;

  // Queue up to the currently available TCP send-buffer capacity. Returns the
  // number accepted by lwIP; callers can retry the remainder after poll().
  std::size_t write(std::span<const std::uint8_t> data);
  std::vector<std::uint8_t> read_available(std::size_t max_bytes = static_cast<std::size_t>(-1));
  void shutdown_write();
  void close();

 private:
  explicit LwipTcpStream(std::shared_ptr<Impl> impl);
  std::shared_ptr<Impl> impl_;
  friend class LwipStack;
  friend class LwipTcpListener;
};

class LwipTcpListener {
 public:
  struct Impl;

  ~LwipTcpListener();
  LwipTcpListener(const LwipTcpListener&) = delete;
  LwipTcpListener& operator=(const LwipTcpListener&) = delete;

  std::uint16_t port() const noexcept;
  std::shared_ptr<LwipTcpStream> accept();
  void close();

 private:
  explicit LwipTcpListener(std::shared_ptr<Impl> impl);
  std::shared_ptr<Impl> impl_;
  friend class LwipStack;
};

class LwipStack {
 public:
  using SendIp = std::function<void(std::vector<std::uint8_t>)>;

  LwipStack(Ip6Address local_address, SendIp send_ip);
  ~LwipStack();
  LwipStack(const LwipStack&) = delete;
  LwipStack& operator=(const LwipStack&) = delete;

  const Ip6Address& local_address() const noexcept;
  std::shared_ptr<LwipTcpListener> listen(std::uint16_t port);
  std::shared_ptr<LwipTcpStream> connect(const Ip6Address& remote, std::uint16_t port);

  // Inject one fully formed IPv6 packet from the encrypted Tailcat tunnel.
  void input_ip(std::span<const std::uint8_t> packet);
  // Drive lwIP timers; call regularly from the Tailcat network event loop.
  void poll();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tailcat
