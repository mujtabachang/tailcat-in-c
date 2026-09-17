// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/wireguard_derp.hpp"

#include "tailcat/derp.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace tailcat {
namespace {

using Clock = std::chrono::steady_clock;

std::chrono::milliseconds remaining_ms(Clock::time_point deadline) {
  const auto now = Clock::now();
  if (now >= deadline) return std::chrono::milliseconds(0);
  auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
  if (remaining.count() == 0) remaining = std::chrono::milliseconds(1);
  return remaining;
}

}  // namespace

WireGuardDerpPeer::WireGuardDerpPeer(DerpTransport& transport,
                                     NodeKeyPair local_identity,
                                     Key32 peer_public,
                                     std::optional<Key32> preshared_key)
    : transport_(transport),
      peer_public_(peer_public),
      wireguard_(std::move(local_identity), peer_public_, std::move(preshared_key)) {}

bool WireGuardDerpPeer::receive_one_for(
    std::chrono::milliseconds timeout,
    std::optional<std::vector<std::uint8_t>>& plaintext) {
  auto frame = transport_.receive_for(timeout);
  if (!frame) return false;

  switch (frame->type) {
    case DerpFrameType::Ping: {
      if (frame->payload.size() == 8U) {
        std::array<std::uint8_t, 8> value{};
        std::copy(frame->payload.begin(), frame->payload.end(), value.begin());
        transport_.send_pong(value);
      }
      return true;
    }
    case DerpFrameType::KeepAlive:
    case DerpFrameType::Health:
    case DerpFrameType::PeerPresent:
    case DerpFrameType::PeerGone:
    case DerpFrameType::Restarting:
      return true;
    case DerpFrameType::RecvPacket: {
      Key32 source{};
      std::vector<std::uint8_t> packet;
      if (!parse_derp_recv_packet(frame->payload, source, packet)) {
        throw std::runtime_error("malformed DERP RecvPacket frame");
      }
      if (source != peer_public_) return true;

      auto result = wireguard_.handle_packet(packet);
      if (!result.outbound.empty()) {
        transport_.send_packet(peer_public_, result.outbound);
      }
      if (result.plaintext_ip) plaintext = std::move(result.plaintext_ip);
      return true;
    }
    default:
      return true;
  }
}

void WireGuardDerpPeer::connect(std::chrono::milliseconds timeout) {
  if (timeout.count() <= 0) throw std::invalid_argument("WireGuard connect timeout must be positive");
  if (wireguard_.session_established()) return;

  const auto deadline = Clock::now() + timeout;
  auto next_send = Clock::now();
  for (;;) {
    auto now = Clock::now();
    if (wireguard_.session_established()) return;
    if (now >= deadline) {
      throw std::runtime_error("timed out establishing WireGuard session over DERP");
    }

    if (now >= next_send) {
      transport_.send_packet(peer_public_, wireguard_.create_handshake_initiation());
      next_send = now + std::chrono::seconds(5);
    }

    now = Clock::now();
    const auto wake = std::min(next_send, deadline);
    auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(wake - now);
    if (wait.count() <= 0) wait = std::chrono::milliseconds(1);
    std::optional<std::vector<std::uint8_t>> ignored;
    (void)receive_one_for(wait, ignored);
  }
}

std::optional<std::vector<std::uint8_t>> WireGuardDerpPeer::pump_for(
    std::chrono::milliseconds timeout) {
  if (timeout.count() < 0) throw std::invalid_argument("negative WireGuard pump timeout");
  const auto deadline = Clock::now() + timeout;
  for (;;) {
    const auto remaining = remaining_ms(deadline);
    if (remaining.count() == 0) return std::nullopt;
    std::optional<std::vector<std::uint8_t>> plaintext;
    if (!receive_one_for(remaining, plaintext)) return std::nullopt;
    if (plaintext) return plaintext;
  }
}

void WireGuardDerpPeer::send_ip_packet(std::span<const std::uint8_t> packet) {
  if (!wireguard_.session_established()) {
    throw std::runtime_error("WireGuard session is not established");
  }
  transport_.send_packet(peer_public_, wireguard_.encrypt_ip_packet(packet));
}

bool WireGuardDerpPeer::session_established() const noexcept {
  return wireguard_.session_established();
}

const Key32& WireGuardDerpPeer::peer_public_key() const noexcept {
  return peer_public_;
}

}  // namespace tailcat
