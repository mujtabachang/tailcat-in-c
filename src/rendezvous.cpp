// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/rendezvous.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace tailcat {
namespace {

using Clock = std::chrono::steady_clock;

struct ReceivedPacket {
  Key32 source{};
  std::vector<std::uint8_t> packet;
};

std::chrono::milliseconds remaining_ms(Clock::time_point deadline) {
  const auto now = Clock::now();
  if (now >= deadline) return std::chrono::milliseconds(0);
  auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
  if (remaining.count() == 0) remaining = std::chrono::milliseconds(1);
  return remaining;
}

std::optional<ReceivedPacket> receive_packet_for(DerpTransport& transport,
                                                 std::chrono::milliseconds timeout) {
  if (timeout.count() < 0) throw std::invalid_argument("negative DERP receive timeout");
  const auto deadline = Clock::now() + timeout;
  for (;;) {
    const auto remaining = remaining_ms(deadline);
    if (remaining.count() == 0) return std::nullopt;

    auto frame = transport.receive_for(remaining);
    if (!frame) return std::nullopt;

    switch (frame->type) {
      case DerpFrameType::Ping: {
        if (frame->payload.size() == 8U) {
          std::array<std::uint8_t, 8> value{};
          std::copy(frame->payload.begin(), frame->payload.end(), value.begin());
          transport.send_pong(value);
        }
        break;
      }
      case DerpFrameType::KeepAlive:
      case DerpFrameType::Health:
      case DerpFrameType::PeerPresent:
      case DerpFrameType::PeerGone:
      case DerpFrameType::Restarting:
        break;
      case DerpFrameType::RecvPacket: {
        ReceivedPacket out;
        if (!parse_derp_recv_packet(frame->payload, out.source, out.packet)) {
          throw std::runtime_error("malformed DERP RecvPacket frame");
        }
        return out;
      }
      default:
        // Other server frames are valid DERP traffic but not part of Tailcat's
        // rendezvous. Ignore them here; the data-plane loop handles its own
        // packet/control traffic after rendezvous completes.
        break;
    }
  }
}

}  // namespace

std::chrono::milliseconds rendezvous_client(DerpTransport& transport,
                                             const NodeKeyPair& node_identity,
                                             const Key32& disco_public,
                                             const Key32& server_public,
                                             std::chrono::milliseconds timeout) {
  if (timeout.count() <= 0) throw std::invalid_argument("rendezvous timeout must be positive");

  const auto packet = encode_meow_ping(node_identity.public_key, disco_public);
  const auto started = Clock::now();
  const auto deadline = started + timeout;
  auto next_send = started;
  std::string last_send_error;

  for (;;) {
    auto now = Clock::now();
    if (now >= deadline) {
      std::string message = "timed out waiting for Tailcat MEOWED acknowledgment";
      if (!last_send_error.empty()) message += " (last send error: " + last_send_error + ")";
      throw std::runtime_error(message);
    }

    if (now >= next_send) {
      try {
        transport.send_packet(server_public, packet);
        last_send_error.clear();
      } catch (const std::exception& e) {
        // Match upstream Tailcat's behavior: a DERP send failure is treated as
        // packet loss and retried until the rendezvous timeout expires.
        last_send_error = e.what();
      }
      next_send = now + std::chrono::seconds(1);
    }

    now = Clock::now();
    const auto wake = std::min(next_send, deadline);
    auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(wake - now);
    if (wait.count() <= 0) wait = std::chrono::milliseconds(1);

    const auto incoming = receive_packet_for(transport, wait);
    if (!incoming) continue;
    if (incoming->source != server_public) continue;
    if (!is_meowed_packet(incoming->packet)) continue;

    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started);
  }
}

std::optional<RendezvousPeer> rendezvous_server_once(
    DerpTransport& transport, std::chrono::milliseconds timeout,
    const std::function<bool(const Key32&)>& allow) {
  if (timeout.count() < 0) throw std::invalid_argument("negative rendezvous timeout");
  const auto deadline = Clock::now() + timeout;

  for (;;) {
    const auto remaining = remaining_ms(deadline);
    if (remaining.count() == 0) return std::nullopt;
    const auto incoming = receive_packet_for(transport, remaining);
    if (!incoming) return std::nullopt;
    if (!is_meow_packet(incoming->packet) || is_meowed_packet(incoming->packet)) continue;

    Key32 embedded_node{};
    Key32 disco_public{};
    if (!parse_meow_ping(incoming->packet, embedded_node, disco_public)) continue;

    // Upstream Tailcat deliberately treats DERP's authenticated source key as
    // the client identity. The node key duplicated inside MEOW is not trusted
    // for peer identity; retaining that rule is important for wire parity.
    if (allow && !allow(incoming->source)) continue;

    transport.send_packet(incoming->source, encode_meowed());
    return RendezvousPeer{incoming->source, disco_public};
  }
}

}  // namespace tailcat
