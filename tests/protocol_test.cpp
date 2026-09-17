// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/protocol.hpp"

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace {

tailcat::Key32 sequence(std::uint8_t start) {
  tailcat::Key32 out{};
  for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(start + static_cast<std::uint8_t>(i));
  return out;
}

}  // namespace

int main() {
  // This is an address literal from upstream tailscale/tailcat's CLI tests.
  // It contains ServerPublic = 00 01 02 00... and RegionID = 10.
  const std::string upstream = "tcomFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCg";
  const auto parsed = tailcat::parse_tailcat_addr(upstream);
  assert(parsed.server_public[0] == 0x00U);
  assert(parsed.server_public[1] == 0x01U);
  assert(parsed.server_public[2] == 0x02U);
  assert(parsed.region_id == 10);
  assert(!parsed.server_disco_public.has_value());
  assert(tailcat::encode_tailcat_addr(parsed) == upstream);

  tailcat::ConnInfo full;
  full.server_public = sequence(1U);
  full.server_disco_public = sequence(33U);
  full.preshared_key = sequence(65U);
  full.region_id = 302;
  tailcat::DerpRegion region;
  region.region_id = 302;
  region.region_code = "sfo";
  region.region_name = "San Francisco";
  tailcat::DerpNode node;
  node.name = "1a";
  node.region_id = 302;
  node.host_name = "derp.example.test";
  node.ipv4 = "192.0.2.1";
  node.derp_port = 443;
  region.nodes.push_back(node);
  full.regions.push_back(region);

  const auto encoded = tailcat::encode_tailcat_addr(full);
  assert(encoded.rfind("tc", 0) == 0);
  const auto decoded = tailcat::parse_tailcat_addr(encoded);
  assert(decoded.server_public == full.server_public);
  assert(decoded.server_disco_public == full.server_disco_public);
  assert(decoded.preshared_key == full.preshared_key);
  assert(decoded.region_id == 302);
  assert(decoded.regions.size() == 1U);
  assert(decoded.regions[0].nodes.size() == 1U);
  assert(decoded.regions[0].nodes[0].derp_port == 443);

  const auto node_key = sequence(5U);
  const auto disco_key = sequence(55U);
  const auto meow = tailcat::encode_meow_ping(node_key, disco_key);
  assert(meow.size() == 69U);
  assert(tailcat::is_meow_packet(meow));
  tailcat::Key32 got_node{};
  tailcat::Key32 got_disco{};
  assert(tailcat::parse_meow_ping(meow, got_node, got_disco));
  assert(got_node == node_key);
  assert(got_disco == disco_key);
  assert(tailcat::is_meowed_packet(tailcat::encode_meowed()));

  tailcat::Key32 zero{};
  const auto invalid = tailcat::encode_meow_ping(node_key, zero);
  assert(!tailcat::parse_meow_ping(invalid, got_node, got_disco));

  bool rejected = false;
  try {
    (void)tailcat::parse_tailcat_addr("not-a-tailcat-address");
  } catch (const std::runtime_error&) {
    rejected = true;
  }
  assert(rejected);
  return 0;
}
