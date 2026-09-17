#pragma once

#include "tailcat/common.hpp"

#include <optional>
#include <string>
#include <vector>

namespace tailcat {

struct DerpNode {
  std::string name;
  std::string host_name;
  std::string cert_name;
  std::string ipv4;
  std::string ipv6;
  std::uint16_t derp_port = 443;
  bool insecure_for_tests = false;
};

struct ConnInfo {
  Key32 server_public{};
  Key32 preshared_key{};
  std::int64_t region_id = 0;
  std::vector<DerpNode> nodes;
};

std::string encode_address(const ConnInfo& info);
ConnInfo parse_address(std::string_view address);
std::string address_to_json(const ConnInfo& info);

}  // namespace tailcat
