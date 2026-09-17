// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/ip.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace tailcat {

struct LwipUdpDatagram {
  Ip6Address remote_address{};
  std::uint16_t remote_port = 0;
  std::vector<std::uint8_t> payload;
};

// A raw-API lwIP UDP PCB attached to Tailcat's single in-process netif.
// The owning LwipStack must outlive every LwipUdpSocket.
class LwipUdpSocket {
 public:
  struct Impl;

  ~LwipUdpSocket();
  LwipUdpSocket(const LwipUdpSocket&) = delete;
  LwipUdpSocket& operator=(const LwipUdpSocket&) = delete;

  static std::shared_ptr<LwipUdpSocket> bind(std::uint16_t port = 0);
  static std::shared_ptr<LwipUdpSocket> connect(const Ip6Address& remote,
                                                std::uint16_t port);

  std::uint16_t local_port() const noexcept;
  bool connected() const noexcept;
  bool open() const noexcept;

  void send(std::span<const std::uint8_t> payload);
  void send_to(const Ip6Address& remote, std::uint16_t port,
               std::span<const std::uint8_t> payload);
  std::optional<LwipUdpDatagram> receive();
  void close() noexcept;

 private:
  explicit LwipUdpSocket(std::shared_ptr<Impl> impl);
  std::shared_ptr<Impl> impl_;
};

}  // namespace tailcat
