// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <array>
#include <cstdint>
#include <optional>
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

ConnInfo parse_tailcat_addr(std::string_view addr);
std::string encode_tailcat_addr(const ConnInfo& info);

std::vector<std::uint8_t> encode_meow_ping(const Key32& node_public, const Key32& disco_public);
std::vector<std::uint8_t> encode_meowed();
bool is_meow_packet(const std::vector<std::uint8_t>& packet) noexcept;
bool is_meowed_packet(const std::vector<std::uint8_t>& packet) noexcept;
bool parse_meow_ping(const std::vector<std::uint8_t>& packet, Key32& node_public, Key32& disco_public) noexcept;

}  // namespace tailcat
