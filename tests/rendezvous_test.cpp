// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/crypto.hpp"
#include "tailcat/rendezvous.hpp"

#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <utility>
#include <vector>

namespace {

class FakeDerpTransport final : public tailcat::DerpTransport {
 public:
  struct SentPacket {
    tailcat::Key32 destination{};
    std::vector<std::uint8_t> packet;
  };

  void send_packet(const tailcat::Key32& destination,
                   const std::vector<std::uint8_t>& packet) override {
    sent.push_back(SentPacket{destination, packet});
  }

  void send_pong(const std::array<std::uint8_t, 8>& value) override {
    pongs.push_back(value);
  }

  std::optional<tailcat::DerpFrame> receive_for(std::chrono::milliseconds) override {
    if (incoming.empty()) return std::nullopt;
    auto frame = std::move(incoming.front());
    incoming.pop_front();
    return frame;
  }

  void push_packet(const tailcat::Key32& source, const std::vector<std::uint8_t>& packet) {
    incoming.push_back(tailcat::DerpFrame{
        tailcat::DerpFrameType::RecvPacket,
        tailcat::make_derp_send_packet(source, packet),
    });
  }

  std::deque<tailcat::DerpFrame> incoming;
  std::vector<SentPacket> sent;
  std::vector<std::array<std::uint8_t, 8>> pongs;
};

}  // namespace

int main() {
  tailcat::initialize_crypto();

  const auto client = tailcat::generate_node_key();
  const auto client_disco = tailcat::derive_disco_key(client.private_key);
  const auto server = tailcat::generate_node_key();

  {
    FakeDerpTransport transport;
    transport.push_packet(server.public_key, tailcat::encode_meowed());
    const auto latency = tailcat::rendezvous_client(
        transport, client, client_disco.public_key, server.public_key,
        std::chrono::seconds(1));
    assert(latency >= std::chrono::milliseconds(0));
    assert(!transport.sent.empty());
    assert(transport.sent.front().destination == server.public_key);
    tailcat::Key32 embedded_node{};
    tailcat::Key32 disco_public{};
    assert(tailcat::parse_meow_ping(transport.sent.front().packet, embedded_node,
                                    disco_public));
    assert(embedded_node == client.public_key);
    assert(disco_public == client_disco.public_key);
  }

  {
    FakeDerpTransport transport;
    const std::array<std::uint8_t, 8> ping{{1, 2, 3, 4, 5, 6, 7, 8}};
    transport.incoming.push_back(tailcat::DerpFrame{
        tailcat::DerpFrameType::Ping,
        std::vector<std::uint8_t>(ping.begin(), ping.end()),
    });
    transport.push_packet(
        client.public_key,
        tailcat::encode_meow_ping(client.public_key, client_disco.public_key));

    const auto peer = tailcat::rendezvous_server_once(
        transport, std::chrono::seconds(1));
    assert(peer.has_value());
    assert(peer->node_public == client.public_key);
    assert(peer->disco_public == client_disco.public_key);
    assert(transport.pongs.size() == 1U);
    assert(transport.pongs.front() == ping);
    assert(transport.sent.size() == 1U);
    assert(transport.sent.front().destination == client.public_key);
    assert(tailcat::is_meowed_packet(transport.sent.front().packet));
  }

  {
    FakeDerpTransport transport;
    const auto denied = tailcat::generate_node_key();
    const auto denied_disco = tailcat::derive_disco_key(denied.private_key);
    transport.push_packet(
        denied.public_key,
        tailcat::encode_meow_ping(denied.public_key, denied_disco.public_key));
    transport.push_packet(
        client.public_key,
        tailcat::encode_meow_ping(client.public_key, client_disco.public_key));

    const auto peer = tailcat::rendezvous_server_once(
        transport, std::chrono::seconds(1),
        [&](const tailcat::Key32& key) { return key == client.public_key; });
    assert(peer.has_value());
    assert(peer->node_public == client.public_key);
    assert(transport.sent.size() == 1U);
    assert(transport.sent.front().destination == client.public_key);
  }

  return 0;
}
