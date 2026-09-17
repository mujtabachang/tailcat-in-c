// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/crypto.hpp"
#include "tailcat/derp_transport.hpp"
#include "tailcat/ip.hpp"
#include "tailcat/wireguard_derp.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;

class FakeTransport final : public tailcat::DerpTransport {
 public:
  explicit FakeTransport(tailcat::Key32 identity) : identity_(identity) {}

  void link(FakeTransport& peer) { peer_ = &peer; }

  void send_packet(const tailcat::Key32& destination,
                   const std::vector<std::uint8_t>& packet) override {
    if (peer_ == nullptr || destination != peer_->identity_) {
      throw std::runtime_error("fake DERP destination is not connected");
    }
    tailcat::DerpFrame frame;
    frame.type = tailcat::DerpFrameType::RecvPacket;
    frame.payload.reserve(identity_.size() + packet.size());
    frame.payload.insert(frame.payload.end(), identity_.begin(), identity_.end());
    frame.payload.insert(frame.payload.end(), packet.begin(), packet.end());
    peer_->push(std::move(frame));
  }

  void send_pong(const std::array<std::uint8_t, 8>&) override {}

  std::optional<tailcat::DerpFrame> receive_for(
      std::chrono::milliseconds timeout) override {
    std::unique_lock lock(mu_);
    if (!cv_.wait_for(lock, timeout, [&] { return !frames_.empty(); })) {
      return std::nullopt;
    }
    auto frame = std::move(frames_.front());
    frames_.pop_front();
    return frame;
  }

 private:
  void push(tailcat::DerpFrame frame) {
    {
      std::lock_guard lock(mu_);
      frames_.push_back(std::move(frame));
    }
    cv_.notify_one();
  }

  tailcat::Key32 identity_{};
  FakeTransport* peer_ = nullptr;
  std::mutex mu_;
  std::condition_variable cv_;
  std::deque<tailcat::DerpFrame> frames_;
};

std::vector<std::uint8_t> ipv6_packet(const tailcat::Key32& source_key,
                                      const tailcat::Key32& destination_key,
                                      std::string_view payload) {
  assert(payload.size() <= 65535U);
  std::vector<std::uint8_t> packet(40U + payload.size(), 0U);
  packet[0] = 0x60U;
  packet[4] = static_cast<std::uint8_t>(payload.size() >> 8U);
  packet[5] = static_cast<std::uint8_t>(payload.size());
  packet[6] = 59U;
  packet[7] = 64U;
  const auto source = tailcat::tailcat_ip_for_node(source_key);
  const auto destination = tailcat::tailcat_ip_for_node(destination_key);
  std::copy(source.begin(), source.end(), packet.begin() + 8);
  std::copy(destination.begin(), destination.end(), packet.begin() + 24);
  std::copy(payload.begin(), payload.end(), packet.begin() + 40);
  return packet;
}

}  // namespace

int main() {
  tailcat::initialize_crypto();
  const auto client_identity = tailcat::generate_node_key();
  const auto server_identity = tailcat::generate_node_key();
  const auto psk = tailcat::generate_secret_key();

  FakeTransport client_transport(client_identity.public_key);
  FakeTransport server_transport(server_identity.public_key);
  client_transport.link(server_transport);
  server_transport.link(client_transport);

  tailcat::WireGuardDerpPeer client(client_transport, client_identity,
                                    server_identity.public_key, psk);
  tailcat::WireGuardDerpPeer server(server_transport, server_identity,
                                    client_identity.public_key, psk);

  std::exception_ptr server_error;
  std::thread server_handshake([&] {
    try {
      while (!server.session_established()) {
        (void)server.pump_for(250ms);
      }
    } catch (...) {
      server_error = std::current_exception();
    }
  });

  client.connect(2s);
  server_handshake.join();
  if (server_error) std::rethrow_exception(server_error);
  assert(client.session_established());
  assert(server.session_established());

  const auto request = ipv6_packet(client_identity.public_key,
                                   server_identity.public_key,
                                   "native WireGuard carried by DERP");
  client.send_ip_packet(request);
  const auto received_request = server.pump_for(1s);
  assert(received_request.has_value());
  assert(*received_request == request);

  const auto reply = ipv6_packet(server_identity.public_key,
                                 client_identity.public_key,
                                 "encrypted DERP reply");
  server.send_ip_packet(reply);
  const auto received_reply = client.pump_for(1s);
  assert(received_reply.has_value());
  assert(*received_reply == reply);

  return 0;
}
