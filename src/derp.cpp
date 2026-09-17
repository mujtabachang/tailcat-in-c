// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/derp.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace tailcat {
namespace {

constexpr std::array<std::uint8_t, 8> kDerpMagic = {0x44U, 0x45U, 0x52U, 0x50U, 0xf0U, 0x9fU, 0x94U, 0x91U};
constexpr std::size_t kDerpMaxPacket = 64U << 10U;

bool valid_app_name(const std::string& name) {
  if (name.size() > 32U) return false;
  return std::all_of(name.begin(), name.end(), [](unsigned char c) { return c >= 0x20U && c <= 0x7eU; });
}

std::string client_info_json(const std::string& app_name, bool can_ack_pings) {
  if (!valid_app_name(app_name)) throw std::runtime_error("invalid DERP app name");
  std::string json = "{\"version\":2,\"CanAckPings\":";
  json += can_ack_pings ? "true" : "false";
  if (!app_name.empty()) {
    json += ",\"AppName\":\"";
    // ValidAppName allows printable ASCII, so escape the two JSON metacharacters.
    for (const char c : app_name) {
      if (c == '\\' || c == '"') json.push_back('\\');
      json.push_back(c);
    }
    json.push_back('"');
  }
  json.push_back('}');
  return json;
}

}  // namespace

std::vector<std::uint8_t> encode_derp_frame(DerpFrameType type, const std::vector<std::uint8_t>& payload) {
  if (payload.size() > 10U * 1024U * 1024U ||
      payload.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
    throw std::runtime_error("unreasonably large DERP frame");
  }
  const auto len = static_cast<std::uint32_t>(payload.size());
  std::vector<std::uint8_t> out;
  out.reserve(5U + payload.size());
  out.push_back(static_cast<std::uint8_t>(type));
  out.push_back(static_cast<std::uint8_t>((len >> 24U) & 0xffU));
  out.push_back(static_cast<std::uint8_t>((len >> 16U) & 0xffU));
  out.push_back(static_cast<std::uint8_t>((len >> 8U) & 0xffU));
  out.push_back(static_cast<std::uint8_t>(len & 0xffU));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

DerpFrame decode_derp_frame(const std::vector<std::uint8_t>& frame) {
  if (frame.size() < 5U) throw std::runtime_error("short DERP frame header");
  const std::uint32_t len = (static_cast<std::uint32_t>(frame[1]) << 24U) |
                            (static_cast<std::uint32_t>(frame[2]) << 16U) |
                            (static_cast<std::uint32_t>(frame[3]) << 8U) |
                            static_cast<std::uint32_t>(frame[4]);
  if (frame.size() != 5U + static_cast<std::size_t>(len)) throw std::runtime_error("DERP frame length mismatch");
  DerpFrame out;
  out.type = static_cast<DerpFrameType>(frame[0]);
  out.payload.assign(frame.begin() + 5, frame.end());
  return out;
}

Key32 parse_derp_server_key(const std::vector<std::uint8_t>& payload) {
  if (payload.size() < 40U || !std::equal(kDerpMagic.begin(), kDerpMagic.end(), payload.begin())) {
    throw std::runtime_error("invalid DERP server greeting");
  }
  Key32 out{};
  std::copy_n(payload.begin() + 8, 32, out.begin());
  return out;
}

std::vector<std::uint8_t> make_derp_client_info(const NodeKeyPair& client, const Key32& server_public,
                                                std::string app_name, bool can_ack_pings) {
  const auto json = client_info_json(app_name, can_ack_pings);
  const std::vector<std::uint8_t> clear(json.begin(), json.end());
  const auto boxed = nacl_box_seal(client.private_key, server_public, clear);
  std::vector<std::uint8_t> payload;
  payload.reserve(client.public_key.size() + boxed.size());
  payload.insert(payload.end(), client.public_key.begin(), client.public_key.end());
  payload.insert(payload.end(), boxed.begin(), boxed.end());
  return payload;
}

std::string open_derp_server_info(const NodeKeyPair& client, const Key32& server_public,
                                  const std::vector<std::uint8_t>& payload) {
  const auto clear = nacl_box_open(client.private_key, server_public, payload);
  return std::string(clear.begin(), clear.end());
}

std::vector<std::uint8_t> make_derp_send_packet(const Key32& destination,
                                                const std::vector<std::uint8_t>& packet) {
  if (packet.size() > kDerpMaxPacket) throw std::runtime_error("DERP packet exceeds 64 KiB");
  std::vector<std::uint8_t> out;
  out.reserve(destination.size() + packet.size());
  out.insert(out.end(), destination.begin(), destination.end());
  out.insert(out.end(), packet.begin(), packet.end());
  return out;
}

bool parse_derp_recv_packet(const std::vector<std::uint8_t>& payload, Key32& source,
                            std::vector<std::uint8_t>& packet) {
  // Tailcat speaks DERP protocol version 2, where FrameRecvPacket starts with
  // the sender's raw 32-byte node public key.
  if (payload.size() < 32U) return false;
  std::copy_n(payload.begin(), 32, source.begin());
  packet.assign(payload.begin() + 32, payload.end());
  return packet.size() <= kDerpMaxPacket;
}

}  // namespace tailcat
