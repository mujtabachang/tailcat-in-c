// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/crypto.hpp"
#include "tailcat/data_plane.hpp"
#include "tailcat/derp.hpp"
#include "tailcat/ip.hpp"
#include "tailcat/protocol.hpp"
#include "tailcat/wireguard_engine.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

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

int main() try {
  using namespace std::chrono_literals;
  tailcat::initialize_crypto();
  const auto server_identity = tailcat::generate_node_key();
  const auto client_identity = tailcat::generate_node_key();
  const auto client_disco = tailcat::derive_disco_key(client_identity.private_key);
  const auto denied_identity = tailcat::generate_node_key();
  const auto denied_disco = tailcat::derive_disco_key(denied_identity.private_key);
  const auto psk = tailcat::generate_secret_key();

  FakeDerp derp;
  tailcat::TailcatServerDataPlane server(
      derp, server_identity, psk,
      [allowed = client_identity.public_key](const tailcat::Key32& peer) {
        return peer == allowed;
      });
  auto listener = server.listen(1);
  require(listener->port() == 1U, "server listener did not bind TCP port 1");

  std::cerr << "stage: denied meow\n";
  derp.inject(denied_identity.public_key,
              tailcat::encode_meow_ping(denied_identity.public_key,
                                         denied_disco.public_key));
  require(server.pump_for(1ms), "server did not consume denied MEOW frame");
  require(server.peer_count() == 0U, "denied MEOW created a server peer");
  require(derp.sent.empty(), "denied MEOW received an acknowledgement");

  std::cerr << "stage: allowed meow\n";
  derp.inject(client_identity.public_key,
              tailcat::encode_meow_ping(client_identity.public_key,
                                         client_disco.public_key));
  require(server.pump_for(1ms), "server did not consume MEOW frame");
  require(server.peer_count() == 1U, "MEOW did not create server peer");
  require(server.has_peer(client_identity.public_key), "server peer key mismatch");
  require(derp.sent.size() == 1U, "server did not send one MEOWED packet");
  require(derp.sent.back().first == client_identity.public_key,
          "MEOWED destination mismatch");
  require(tailcat::is_meowed_packet(derp.sent.back().second),
          "server response was not MEOWED");

  std::cerr << "stage: wireguard handshake\n";
  tailcat::WireGuardPeerEngine client_wireguard(
      client_identity, server_identity.public_key, psk);
  derp.sent.clear();
  derp.inject(client_identity.public_key,
              client_wireguard.create_handshake_initiation());
  require(server.pump_for(1ms), "server did not consume WireGuard initiation");
  require(derp.sent.size() == 1U, "server did not send WireGuard response");
  const auto response = client_wireguard.handle_packet(derp.sent.back().second);
  require(response.session_established, "client rejected WireGuard response");
  require(client_wireguard.session_established(), "client WireGuard session not established");
  require(server.peer_session_established(client_identity.public_key),
          "server WireGuard session not established");

  std::cerr << "stage: transport into lwip\n";
  const auto plaintext = ipv6_packet(
      tailcat::tailcat_ip_for_node(client_identity.public_key),
      tailcat::tailcat_ip_for_node(server_identity.public_key));
  derp.inject(client_identity.public_key,
              client_wireguard.encrypt_ip_packet(plaintext));
  require(server.pump_for(1ms), "server did not consume WireGuard transport packet");

  std::cerr << "stage: teardown\n";
  listener->close();
  std::cerr << "stage: done\n";
  return 0;
} catch (const std::exception& e) {
  std::cerr << "tailcat_data_plane_test: " << e.what() << '\n';
  return 1;
}
