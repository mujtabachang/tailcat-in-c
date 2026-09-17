// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/crypto.hpp"
#include "tailcat/derp_transport.hpp"
#include "tailcat/ip.hpp"
#include "tailcat/lwip_stack.hpp"
#include "tailcat/lwip_udp.hpp"
#include "tailcat/protocol.hpp"
#include "tailcat/wireguard_derp.hpp"
#include "tailcat/wireguard_engine.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>

namespace tailcat {

// Client-side Tailcat data plane: MEOW rendezvous, a WireGuard peer carried by
// DERP, and one raw-IP lwIP interface exposing TCP/UDP to the application.
class TailcatClientDataPlane {
 public:
  TailcatClientDataPlane(DerpTransport& transport, NodeKeyPair identity,
                         ConnInfo server_info);
  ~TailcatClientDataPlane();
  TailcatClientDataPlane(const TailcatClientDataPlane&) = delete;
  TailcatClientDataPlane& operator=(const TailcatClientDataPlane&) = delete;

  void connect(std::chrono::milliseconds timeout = std::chrono::seconds(15));
  std::shared_ptr<LwipTcpStream> dial(std::uint16_t port);
  std::shared_ptr<LwipUdpSocket> dial_udp(std::uint16_t port);
  bool pump_for(std::chrono::milliseconds timeout);

  bool session_established() const noexcept;
  const Ip6Address& local_address() const noexcept;
  const Ip6Address& server_address() const noexcept;

 private:
  DerpTransport& transport_;
  NodeKeyPair identity_;
  ConnInfo server_info_;
  WireGuardDerpPeer wireguard_;
  Ip6Address server_address_{};
  LwipStack stack_;
};

// Server-side shared data plane. One DERP connection and one lwIP stack serve
// all clients; each authenticated DERP source gets an independent WireGuard
// peer. Outbound lwIP IPv6 packets are routed back to the peer owning the
// destination Tailcat synthetic IPv6 address.
class TailcatServerDataPlane {
 public:
  using AllowPeer = std::function<bool(const Key32&)>;

  TailcatServerDataPlane(DerpTransport& transport, NodeKeyPair identity,
                         std::optional<Key32> preshared_key = std::nullopt,
                         AllowPeer allow = {});
  ~TailcatServerDataPlane();
  TailcatServerDataPlane(const TailcatServerDataPlane&) = delete;
  TailcatServerDataPlane& operator=(const TailcatServerDataPlane&) = delete;

  std::shared_ptr<LwipTcpListener> listen(std::uint16_t port);
  std::shared_ptr<LwipUdpSocket> bind_udp(std::uint16_t port);
  bool pump_for(std::chrono::milliseconds timeout);

  std::size_t peer_count() const noexcept;
  bool has_peer(const Key32& node_public) const noexcept;
  bool peer_session_established(const Key32& node_public) const noexcept;
  const Ip6Address& local_address() const noexcept;

 private:
  struct Peer;
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tailcat
