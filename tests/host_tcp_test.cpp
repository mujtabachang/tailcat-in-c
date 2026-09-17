// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/host_tcp.hpp"
#include "tailcat/platform.hpp"

#include <cassert>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

int main() {
  tailcat::initialize_platform();
  auto listener = tailcat::HostTcpListener::listen("127.0.0.1", 0U);
  assert(listener.port() != 0U);

  std::thread server([&listener] {
    auto stream = listener.accept();
    const auto request = stream->read_some();
    const std::string got(request.begin(), request.end());
    assert(got == "ping");
    const std::string reply = "pong";
    stream->write_all(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(reply.data()), reply.size()));
    stream->shutdown_write();
    stream->close();
  });

  auto client = tailcat::HostTcpStream::connect("127.0.0.1", listener.port());
  const std::string request = "ping";
  client->write_all(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(request.data()), request.size()));
  client->shutdown_write();
  const auto response = client->read_some();
  const std::string got(response.begin(), response.end());
  assert(got == "pong");
  assert(client->read_some().empty());
  client->close();

  server.join();
  listener.close();
  tailcat::shutdown_platform();
  return 0;
}
