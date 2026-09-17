#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace tailcat {

using Key32 = std::array<std::uint8_t, 32>;

struct DerpNode {
  std::string name;
  std::int64_t region_id = 0;
  std::string host_name;
  std::string cert_name;
  std::string ipv4;
  std::string ipv6;
  std::int64_t stun_port = 0;
  std::int64_t derp_port = 0;
  bool insecure_for_tests = false;
};

struct DerpRegion {
  std::int64_t region_id = 0;
  std::string region_code;
  std::string region_name;
  std::vector<DerpNode> nodes;
};

struct ConnInfo {
  Key32 server_public{};
  std::optional<Key32> server_disco_public;
  std::optional<Key32> preshared_key;
  std::vector<DerpRegion> regions;
  std::int64_t region_id = 0;
};

std::string encode_tailcat_addr(const ConnInfo& info);
ConnInfo decode_tailcat_addr(std::string_view addr);
std::array<std::uint8_t, 16> tailcat_ip_for_key(const Key32& key);
std::string format_ipv6(const std::array<std::uint8_t, 16>& addr);

std::vector<std::uint8_t> encode_meow_ping(const Key32& node_key, const Key32& disco_key);
std::vector<std::uint8_t> encode_meowed();
bool is_meow_packet(std::span<const std::uint8_t> packet);
bool is_meowed_packet(std::span<const std::uint8_t> packet);
bool parse_meow_ping(std::span<const std::uint8_t> packet, Key32& node_key, Key32& disco_key);

enum class DerpFrameType : std::uint8_t {
  server_key = 0x01,
  client_info = 0x02,
  server_info = 0x03,
  send_packet = 0x04,
  recv_packet = 0x05,
  keep_alive = 0x06,
  note_preferred = 0x07,
  peer_gone = 0x08,
  peer_present = 0x09,
  forward_packet = 0x0a,
  watch_conns = 0x10,
  close_peer = 0x11,
  ping = 0x12,
  pong = 0x13,
  health = 0x14,
  restarting = 0x15,
};

struct DerpFrameHeader {
  DerpFrameType type{};
  std::uint32_t length = 0;
};

std::array<std::uint8_t, 5> encode_derp_frame_header(DerpFrameType type, std::uint32_t length);
DerpFrameHeader decode_derp_frame_header(std::span<const std::uint8_t> bytes);

}  // namespace tailcat
