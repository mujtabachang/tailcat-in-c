// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/lwip_stack.hpp"
#include "tailcat/lwip_udp.hpp"

#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

int main() {
  const tailcat::Ip6Address local = {
      0xfdU, 0x7aU, 0x11U, 0x5cU, 0xa1U, 0xe0U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U};

  std::optional<std::vector<std::uint8_t>> emitted;
  tailcat::LwipStack stack(local, [&](std::vector<std::uint8_t> packet) {
    emitted = std::move(packet);
  });

  auto server = tailcat::LwipUdpSocket::bind(5353U);
  auto client = tailcat::LwipUdpSocket::connect(local, 5353U);
  const std::string message = "hello-over-udp";
  client->send(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
  assert(emitted.has_value());

  stack.input_ip(*emitted);
  stack.poll();
  const auto received = server->receive();
  assert(received.has_value());
  assert(received->remote_port == client->local_port());
  assert(std::string(received->payload.begin(), received->payload.end()) == message);

  emitted.reset();
  const std::string response = "udp-response";
  server->send_to(received->remote_address, received->remote_port,
                  std::span<const std::uint8_t>(
                      reinterpret_cast<const std::uint8_t*>(response.data()),
                      response.size()));
  assert(emitted.has_value());
  stack.input_ip(*emitted);
  stack.poll();
  const auto reply = client->receive();
  assert(reply.has_value());
  assert(std::string(reply->payload.begin(), reply->payload.end()) == response);

  client->close();
  server->close();
  return 0;
}
