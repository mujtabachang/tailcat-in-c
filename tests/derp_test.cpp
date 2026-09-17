// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/crypto.hpp"
#include "tailcat/derp.hpp"

#include <algorithm>
#include <cassert>
#include <string>
#include <vector>

int main() {
  tailcat::initialize_crypto();

  const auto client = tailcat::generate_node_key();
  const auto server = tailcat::generate_node_key();
  assert(tailcat::node_public_from_private(client.private_key) == client.public_key);

  const auto client_info = tailcat::make_derp_client_info(client, server.public_key, "tailcat-client");
  assert(client_info.size() > 32U);
  assert(std::equal(client.public_key.begin(), client.public_key.end(), client_info.begin()));
  const std::vector<std::uint8_t> boxed(client_info.begin() + 32, client_info.end());
  const auto opened = tailcat::nacl_box_open(server.private_key, client.public_key, boxed);
  const std::string json(opened.begin(), opened.end());
  assert(json.find("\"version\":2") != std::string::npos);
  assert(json.find("\"CanAckPings\":true") != std::string::npos);
  assert(json.find("\"AppName\":\"tailcat-client\"") != std::string::npos);

  std::vector<std::uint8_t> greeting = {0x44U, 0x45U, 0x52U, 0x50U, 0xf0U, 0x9fU, 0x94U, 0x91U};
  greeting.insert(greeting.end(), server.public_key.begin(), server.public_key.end());
  assert(tailcat::parse_derp_server_key(greeting) == server.public_key);

  const std::string server_json = "{\"version\":2}";
  const std::vector<std::uint8_t> server_clear(server_json.begin(), server_json.end());
  const auto server_box = tailcat::nacl_box_seal(server.private_key, client.public_key, server_clear);
  assert(tailcat::open_derp_server_info(client, server.public_key, server_box) == server_json);

  const std::vector<std::uint8_t> payload = {'m', 'e', 'o', 'w'};
  const auto encoded = tailcat::encode_derp_frame(tailcat::DerpFrameType::SendPacket, payload);
  const auto decoded = tailcat::decode_derp_frame(encoded);
  assert(decoded.type == tailcat::DerpFrameType::SendPacket);
  assert(decoded.payload == payload);

  const auto send_payload = tailcat::make_derp_send_packet(server.public_key, payload);
  assert(send_payload.size() == 36U);
  assert(std::equal(server.public_key.begin(), server.public_key.end(), send_payload.begin()));

  std::vector<std::uint8_t> recv_payload(client.public_key.begin(), client.public_key.end());
  recv_payload.insert(recv_payload.end(), payload.begin(), payload.end());
  tailcat::Key32 source{};
  std::vector<std::uint8_t> packet;
  assert(tailcat::parse_derp_recv_packet(recv_payload, source, packet));
  assert(source == client.public_key);
  assert(packet == payload);
  return 0;
}
