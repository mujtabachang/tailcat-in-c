#include "tailcat/protocol.hpp"
#include <cassert>
#include <string>
int main() {
  using namespace tailcat;
  const std::string known = "tcomFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCg";
  const auto ci = decode_tailcat_addr(known);
  assert(ci.region_id == 10);
  assert(ci.server_public[0] == 0x00 && ci.server_public[1] == 0x01 && ci.server_public[2] == 0x02 && ci.server_public[31] == 0x1f);
  assert(encode_tailcat_addr(ci) == known);
  const auto ip = tailcat_ip_for_key(ci.server_public);
  assert(ip[0] == 0xfd && ip[1] == 0x7a && ip[2] == 0x11 && ip[3] == 0x5c && ip[4] == 0xa1 && ip[5] == 0xe0 && ip[6] == 0x00 && ip[7] == 0x01);
  Key32 disco{}; disco.fill(9);
  const auto ping = encode_meow_ping(ci.server_public, disco);
  assert(ping.size() == 69 && is_meow_packet(ping));
  Key32 node_out{}, disco_out{};
  assert(parse_meow_ping(ping, node_out, disco_out));
  assert(node_out == ci.server_public && disco_out == disco);
  assert(is_meowed_packet(encode_meowed()));
  const auto encoded_header = encode_derp_frame_header(DerpFrameType::send_packet, 0x01020304);
  const auto header = decode_derp_frame_header(encoded_header);
  assert(header.type == DerpFrameType::send_packet && header.length == 0x01020304);
  ConnInfo full; full.server_public = ci.server_public; full.server_disco_public = disco;
  Key32 psk{}; psk.fill(7); full.preshared_key = psk;
  DerpRegion region; DerpNode node; node.host_name = "derp.example"; node.derp_port = 443; region.nodes.push_back(node); full.regions.push_back(region);
  const auto round = decode_tailcat_addr(encode_tailcat_addr(full));
  assert(round.server_disco_public == full.server_disco_public && round.preshared_key == full.preshared_key);
  assert(round.regions.size() == 1 && round.regions[0].nodes.size() == 1 && round.regions[0].nodes[0].host_name == "derp.example");
  return 0;
}
