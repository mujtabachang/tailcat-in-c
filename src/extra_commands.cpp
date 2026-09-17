// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/extra_commands.hpp"

#include "tailcat/derp_map.hpp"
#include "tailcat/forward_command.hpp"
#include "tailcat/protocol.hpp"
#include "tailcat/ssh_command.hpp"

#include <iostream>
#include <stdexcept>

namespace tailcat {
namespace {

int run_resolve(const std::vector<std::string>& args) {
  if (args.size() != 1U) {
    throw std::invalid_argument("resolve requires one <tc-address>");
  }
  auto info = parse_tailcat_addr(args[0]);
  if (info.regions.empty()) {
    if (info.region_id == 0) {
      throw std::runtime_error("tailcat address contains no DERP region");
    }
    info.regions.push_back(region_by_id(fetch_derp_map(), info.region_id));
  }
  std::cout << encode_tailcat_addr(info) << '\n';
  return 0;
}

}  // namespace

std::optional<int> run_extra_command(std::string_view command,
                                     const std::vector<std::string>& args,
                                     bool verbose) {
  if (command == "cp") return run_scp_command(args, verbose);
  if (command == "browse") return run_browse_command(args, verbose);
  if (command == "resolve") return run_resolve(args);
  return std::nullopt;
}

}  // namespace tailcat
