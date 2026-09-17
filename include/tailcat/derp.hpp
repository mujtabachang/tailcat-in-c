// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/crypto.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace tailcat {

enum class DerpFrameType : std::uint8_t {
  ServerKey = 0x01,
  ClientInfo = 0x02,
  ServerInfo = 0x03,
  SendPacket = 0x04,
  RecvPacket = 0x05,
  KeepAlive = 0x06,
  NotePreferred = 0x07,
  PeerGone = 0x08,
  PeerPresent = 0x09,
  ForwardPacket = 0x0a,
  WatchConns = 0x10,
  ClosePeer = 0x11,
  Ping = 0x12,
  Pong = 0x13,
  Health = 0x14,
  Restarting = 0x15,
};

struct DerpFrame {
  DerpFrameType type{};
  std::vector<std::uint8_t> payload;
};

std::vector<std::uint8_t> encode_derp_frame(DerpFrameType type, const std::vector<std::uint8_t>& payload);
DerpFrame decode_derp_frame(const std::vector<std::uint8_t>& frame);
Key32 parse_derp_server_key(const std::vector<std::uint8_t>& payload);
std::vector<std::uint8_t> make_derp_client_info(const NodeKeyPair& client, const Key32& server_public,
                                                std::string app_name, bool can_ack_pings = true);
std::string open_derp_server_info(const NodeKeyPair& client, const Key32& server_public,
                                  const std::vector<std::uint8_t>& payload);
std::vector<std::uint8_t> make_derp_send_packet(const Key32& destination,
                                                const std::vector<std::uint8_t>& packet);
bool parse_derp_recv_packet(const std::vector<std::uint8_t>& payload, Key32& source,
                            std::vector<std::uint8_t>& packet);

}  // namespace tailcat
