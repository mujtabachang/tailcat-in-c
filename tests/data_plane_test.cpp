// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/crypto.hpp"
#include "tailcat/data_plane.hpp"
#include "tailcat/derp.hpp"
#include "tailcat/ip.hpp"
#include "tailcat/protocol.hpp"
#include "tailcat/wireguard_engine.hpp"

#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <utility>
#include <vector>

namespace {

class FakeDerp final : public tailcat::DerpTransport {
 public:
  void send_packet(const tailcat::Key32& destination,
                   const std::vector<std::uint8_t>& packet) override {
    sent.emplace_back(destination, packet);
  }

  void send_pong(const std::array<std::uint8_t, 8>& value) override {
    last_pong = value;
  }

  std::optional<tailcat::DerpFrame> receive_for(
      std::chrono::milliseconds) override {
    if (incoming.empty()) return std::nullopt;
    auto frame = std::move(incoming.front());
    incoming.pop_front();
    return frame;
  }

  void inject(const tailcat::Key32& source,
              const std::vector<std::uint8_t>& packet) {
    std::vector<std::uint8_t> payload;
    payload.reserve(source.size() + packet.size());
    payload.insert(payload.end(), source.begin(), source.end());
    payload.insert(payload.end(), packet.begin(), packet.end());
    incoming.push_back(
        tailcat::DerpFrame{tailcat::DerpFrameType::RecvPacket, std::move(payload)});
  }

  std::deque<tailcat::DerpFrame> incoming;
  std::vector<std::pair<tailcat::Key32, std::vector<std::uint8_t>>> sent;
  std::optional<std::array<std::uint8_t, 8>> last_pong;
};

std::vector<std::uint8_t> ipv6_packet(const tailcat::Ip6Address& source,
                                      const tailcat::Ip6Address& destination) {
  std::vector<std::uint8_t> packet(40U, 0U);
  packet[0] = 0x60U;
  packet[6] = 59U;  // No next header.
  packet[7] = 64U;
  for (std::size_t i = 0; i < 16U; ++i) {
    packet[8U + i] = source[i];
    packet[24U + i] = destination[i];
  }
  return packet;
}

}  // namespace

int main() {
  using namespace std::chrono_literals;
  tailcat::initialize_crypto();
  const auto server_identity = tailcat::generate_node_key();
  const auto client_identity = tailcat::generate_node_key();
  const auto client_disco = tailcat::derive_disco_key(client_identity.private_key);
  const auto psk = tailcat::generate_secret_key();

  FakeDerp derp;
  tailcat::TailcatServerDataPlane server(derp, server_identity, psk);
  auto listener = server.listen(1);
  assert(listener->port() == 1U);

  derp.inject(client_identity.public_key,
              tailcat::encode_meow_ping(client_identity.public_key,
                                         client_disco.public_key));
  assert(server.pump_for(1ms));
  assert(server.peer_count() == 1U);
  assert(server.has_peer(client_identity.public_key));
  assert(derp.sent.size() == 1U);
  assert(derp.sent.back().first == client_identity.public_key);
  assert(tailcat::is_meowed_packet(derp.sent.back().second));

  tailcat::WireGuardPeerEngine client_wireguard(
      client_identity, server_identity.public_key, psk);
  derp.sent.clear();
  derp.inject(client_identity.public_key,
              client_wireguard.create_handshake_initiation());
  assert(server.pump_for(1ms));
  assert(derp.sent.size() == 1U);
  const auto response = client_wireguard.handle_packet(derp.sent.back().second);
  assert(response.session_established);
  assert(client_wireguard.session_established());
  assert(server.peer_session_established(client_identity.public_key));

  const auto plaintext = ipv6_packet(
      tailcat::tailcat_ip_for_node(client_identity.public_key),
      tailcat::tailcat_ip_for_node(server_identity.public_key));
  derp.inject(client_identity.public_key,
              client_wireguard.encrypt_ip_packet(plaintext));
  assert(server.pump_for(1ms));

  listener->close();
  return 0;
}
