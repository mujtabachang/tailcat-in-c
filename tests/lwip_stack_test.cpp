// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/crypto.hpp"
#include "tailcat/ip.hpp"
#include "tailcat/lwip_stack.hpp"

#include <cassert>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

int main() {
  tailcat::initialize_crypto();
  const auto identity = tailcat::generate_node_key();
  const auto local = tailcat::tailcat_ip_for_node(identity.public_key);

  std::deque<std::vector<std::uint8_t>> wire;
  tailcat::LwipStack stack(local, [&](std::vector<std::uint8_t> packet) {
    wire.push_back(std::move(packet));
  });

  auto pump = [&] {
    for (int rounds = 0; rounds < 1000; ++rounds) {
      stack.poll();
      if (wire.empty()) return;
      auto packet = std::move(wire.front());
      wire.pop_front();
      stack.input_ip(packet);
    }
    assert(false && "lwIP loop did not quiesce");
  };

  auto listener = stack.listen(24567);
  auto client = stack.connect(local, 24567);
  std::shared_ptr<tailcat::LwipTcpStream> server;
  for (int i = 0; i < 1000 && (!client->connected() || !server); ++i) {
    pump();
    server = listener->accept();
  }
  assert(client->connected());
  assert(server && server->connected());

  const std::string request = "hello through lwIP";
  assert(client->write(std::span<const std::uint8_t>(
             reinterpret_cast<const std::uint8_t*>(request.data()), request.size())) == request.size());
  pump();
  const auto got_request = server->read_available();
  assert(std::string(got_request.begin(), got_request.end()) == request);

  const std::string response = "native userspace TCP works";
  assert(server->write(std::span<const std::uint8_t>(
             reinterpret_cast<const std::uint8_t*>(response.data()), response.size())) == response.size());
  pump();
  const auto got_response = client->read_available();
  assert(std::string(got_response.begin(), got_response.end()) == response);

  client->shutdown_write();
  pump();
  assert(server->eof());

  server->close();
  client->close();
  listener->close();
  return 0;
}
