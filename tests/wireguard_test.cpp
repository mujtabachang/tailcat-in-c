// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/crypto.hpp"
#include "tailcat/wireguard_engine.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>
#include <vector>

namespace {

std::vector<std::uint8_t> ipv6_packet(std::string_view payload) {
  assert(payload.size() <= 65535U);
  std::vector<std::uint8_t> packet(40U + payload.size(), 0U);
  packet[0] = 0x60U;
  packet[4] = static_cast<std::uint8_t>(payload.size() >> 8U);
  packet[5] = static_cast<std::uint8_t>(payload.size());
  packet[6] = 59U;  // No next header; enough for a WireGuard plaintext vector test.
  packet[7] = 64U;
  packet[8] = 0xfdU;
  packet[9] = 0x7aU;
  packet[10] = 0x11U;
  packet[11] = 0x5cU;
  packet[24] = 0xfdU;
  packet[25] = 0x7aU;
  packet[26] = 0x11U;
  packet[27] = 0x5cU;
  std::copy(payload.begin(), payload.end(), packet.begin() + 40);
  return packet;
}

}  // namespace

int main() {
  tailcat::initialize_crypto();
  const auto client_identity = tailcat::generate_node_key();
  const auto server_identity = tailcat::generate_node_key();

  tailcat::Key32 psk{};
  for (std::size_t i = 0; i < psk.size(); ++i) {
    psk[i] = static_cast<std::uint8_t>(i + 1U);
  }

  tailcat::WireGuardPeerEngine client(client_identity, server_identity.public_key, psk);
  tailcat::WireGuardPeerEngine server(server_identity, client_identity.public_key, psk);

  const auto initiation = client.create_handshake_initiation();
  assert(initiation.size() == 148U);
  assert(initiation[0] == 1U);

  const auto on_server = server.handle_packet(initiation);
  assert(on_server.session_established);
  assert(on_server.outbound.size() == 92U);
  assert(on_server.outbound[0] == 2U);

  const auto on_client = client.handle_packet(on_server.outbound);
  assert(on_client.session_established);
  assert(client.session_established());
  assert(server.session_established());

  const auto first_plaintext = ipv6_packet("tailcat native WireGuard over DERP");
  const auto first_ciphertext = client.encrypt_ip_packet(first_plaintext);
  assert(first_ciphertext.size() >= first_plaintext.size() + 32U);
  assert(first_ciphertext[0] == 4U);

  const auto first_received = server.handle_packet(first_ciphertext);
  assert(first_received.plaintext_ip.has_value());
  assert(*first_received.plaintext_ip == first_plaintext);

  // The exact same authenticated packet must be rejected by WireGuard replay protection.
  const auto replayed = server.handle_packet(first_ciphertext);
  assert(!replayed.plaintext_ip.has_value());

  // Once the responder has received transport data it can send on the session too.
  const auto second_plaintext = ipv6_packet("reply from native responder");
  const auto second_ciphertext = server.encrypt_ip_packet(second_plaintext);
  const auto second_received = client.handle_packet(second_ciphertext);
  assert(second_received.plaintext_ip.has_value());
  assert(*second_received.plaintext_ip == second_plaintext);

  return 0;
}
