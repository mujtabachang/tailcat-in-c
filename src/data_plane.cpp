// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/data_plane.hpp"

#include "tailcat/derp.hpp"
#include "tailcat/rendezvous.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace tailcat {

TailcatClientDataPlane::TailcatClientDataPlane(DerpTransport& transport,
                                               NodeKeyPair identity,
                                               ConnInfo server_info)
    : transport_(transport),
      identity_(std::move(identity)),
      server_info_(std::move(server_info)),
      wireguard_(transport_, identity_, server_info_.server_public,
                 server_info_.preshared_key),
      server_address_(tailcat_ip_for_node(server_info_.server_public)),
      stack_(tailcat_ip_for_node(identity_.public_key),
             [this](std::vector<std::uint8_t> packet) {
               wireguard_.send_ip_packet(packet);
             }) {}

TailcatClientDataPlane::~TailcatClientDataPlane() = default;

void TailcatClientDataPlane::connect(std::chrono::milliseconds timeout) {
  if (timeout.count() <= 0) {
    throw std::invalid_argument("Tailcat client connect timeout must be positive");
  }
  const auto disco = derive_disco_key(identity_.private_key);
  (void)rendezvous_client(transport_, identity_, disco.public_key,
                          server_info_.server_public, timeout);
  wireguard_.connect(timeout);
}

std::shared_ptr<LwipTcpStream> TailcatClientDataPlane::dial(std::uint16_t port) {
  if (!wireguard_.session_established()) {
    throw std::runtime_error("Tailcat WireGuard session is not established");
  }
  return stack_.connect(server_address_, port);
}

bool TailcatClientDataPlane::pump_for(std::chrono::milliseconds timeout) {
  if (timeout.count() < 0) throw std::invalid_argument("negative Tailcat pump timeout");
  const auto packet = wireguard_.pump_for(timeout);
  if (packet) stack_.input_ip(*packet);
  stack_.poll();
  return packet.has_value();
}

bool TailcatClientDataPlane::session_established() const noexcept {
  return wireguard_.session_established();
}

const Ip6Address& TailcatClientDataPlane::local_address() const noexcept {
  return stack_.local_address();
}

const Ip6Address& TailcatClientDataPlane::server_address() const noexcept {
  return server_address_;
}

struct TailcatServerDataPlane::Peer {
  Key32 node_public{};
  Key32 disco_public{};
  Ip6Address address{};
  WireGuardPeerEngine wireguard;

  Peer(const NodeKeyPair& local_identity, const Key32& node, const Key32& disco,
       const std::optional<Key32>& psk)
      : node_public(node),
        disco_public(disco),
        address(tailcat_ip_for_node(node)),
        wireguard(local_identity, node, psk) {}
};

struct TailcatServerDataPlane::Impl {
  DerpTransport& transport;
  NodeKeyPair identity;
  std::optional<Key32> psk;
  AllowPeer allow;
  Ip6Address local{};
  std::map<Key32, std::unique_ptr<Peer>> peers;
  std::map<Ip6Address, Peer*> peers_by_ip;
  LwipStack stack;

  Impl(DerpTransport& derp, NodeKeyPair server_identity,
       std::optional<Key32> preshared_key, AllowPeer allow_peer)
      : transport(derp),
        identity(std::move(server_identity)),
        psk(std::move(preshared_key)),
        allow(std::move(allow_peer)),
        local(tailcat_ip_for_node(identity.public_key)),
        stack(local, [this](std::vector<std::uint8_t> packet) {
          send_ip(std::move(packet));
        }) {}

  Peer* peer_for(const Key32& node) noexcept {
    const auto it = peers.find(node);
    return it == peers.end() ? nullptr : it->second.get();
  }

  Peer* add_peer(const Key32& node, const Key32& disco) {
    if (auto* existing = peer_for(node)) {
      existing->disco_public = disco;
      return existing;
    }
    auto peer = std::make_unique<Peer>(identity, node, disco, psk);
    auto* raw = peer.get();
    peers_by_ip.emplace(raw->address, raw);
    peers.emplace(node, std::move(peer));
    return raw;
  }

  void send_ip(std::vector<std::uint8_t> packet) {
    if (packet.size() < 40U || (packet[0] >> 4U) != 6U) return;
    Ip6Address destination{};
    std::copy_n(packet.begin() + 24, destination.size(), destination.begin());
    const auto it = peers_by_ip.find(destination);
    if (it == peers_by_ip.end()) return;
    auto* peer = it->second;
    if (!peer->wireguard.session_established()) return;
    transport.send_packet(peer->node_public,
                          peer->wireguard.encrypt_ip_packet(packet));
  }

  bool handle_frame(DerpFrame frame) {
    switch (frame.type) {
      case DerpFrameType::Ping: {
        if (frame.payload.size() == 8U) {
          std::array<std::uint8_t, 8> value{};
          std::copy(frame.payload.begin(), frame.payload.end(), value.begin());
          transport.send_pong(value);
        }
        return true;
      }
      case DerpFrameType::KeepAlive:
      case DerpFrameType::Health:
      case DerpFrameType::PeerPresent:
      case DerpFrameType::PeerGone:
      case DerpFrameType::Restarting:
        return true;
      case DerpFrameType::RecvPacket:
        break;
      default:
        return true;
    }

    Key32 source{};
    std::vector<std::uint8_t> packet;
    if (!parse_derp_recv_packet(frame.payload, source, packet)) {
      throw std::runtime_error("malformed DERP RecvPacket frame");
    }

    if (is_meowed_packet(packet)) return true;
    if (is_meow_packet(packet)) {
      Key32 embedded_node{};
      Key32 disco{};
      if (!parse_meow_ping(packet, embedded_node, disco)) return true;
      if (allow && !allow(source)) return true;
      (void)add_peer(source, disco);
      // The DERP source key is the authenticated identity. The node key copied
      // into MEOW is deliberately not trusted, matching upstream Tailcat.
      transport.send_packet(source, encode_meowed());
      return true;
    }

    auto* peer = peer_for(source);
    if (peer == nullptr) return true;
    auto result = peer->wireguard.handle_packet(packet);
    if (!result.outbound.empty()) {
      transport.send_packet(source, result.outbound);
    }
    if (result.plaintext_ip) {
      stack.input_ip(*result.plaintext_ip);
    }
    return true;
  }
};

TailcatServerDataPlane::TailcatServerDataPlane(
    DerpTransport& transport, NodeKeyPair identity,
    std::optional<Key32> preshared_key, AllowPeer allow)
    : impl_(std::make_unique<Impl>(transport, std::move(identity),
                                   std::move(preshared_key), std::move(allow))) {}

TailcatServerDataPlane::~TailcatServerDataPlane() = default;

std::shared_ptr<LwipTcpListener> TailcatServerDataPlane::listen(std::uint16_t port) {
  return impl_->stack.listen(port);
}

bool TailcatServerDataPlane::pump_for(std::chrono::milliseconds timeout) {
  if (timeout.count() < 0) throw std::invalid_argument("negative Tailcat pump timeout");
  auto frame = impl_->transport.receive_for(timeout);
  if (!frame) {
    impl_->stack.poll();
    return false;
  }
  const bool handled = impl_->handle_frame(std::move(*frame));
  impl_->stack.poll();
  return handled;
}

std::size_t TailcatServerDataPlane::peer_count() const noexcept {
  return impl_->peers.size();
}

bool TailcatServerDataPlane::has_peer(const Key32& node_public) const noexcept {
  return impl_->peers.find(node_public) != impl_->peers.end();
}

bool TailcatServerDataPlane::peer_session_established(
    const Key32& node_public) const noexcept {
  const auto it = impl_->peers.find(node_public);
  return it != impl_->peers.end() && it->second->wireguard.session_established();
}

const Ip6Address& TailcatServerDataPlane::local_address() const noexcept {
  return impl_->local;
}

}  // namespace tailcat
