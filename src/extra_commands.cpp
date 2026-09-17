// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/extra_commands.hpp"

#include "tailcat/crypto.hpp"
#include "tailcat/derp_map.hpp"
#include "tailcat/forward_command.hpp"
#include "tailcat/protocol.hpp"
#include "tailcat/saved_key.hpp"
#include "tailcat/ssh_command.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

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

std::string lower_ascii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::int64_t resolve_region_argument(std::string_view value, const DerpMap& map) {
  if (value.empty()) return select_derp_region(map).region_id;
  bool numeric = true;
  for (const char c : value) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      numeric = false;
      break;
    }
  }
  if (numeric) {
    const auto id = std::stoll(std::string(value));
    (void)region_by_id(map, id);
    return id;
  }
  const auto wanted = lower_ascii(std::string(value));
  for (const auto& region : map.regions) {
    if (lower_ascii(region.region_code) == wanted) return region.region_id;
  }
  throw std::invalid_argument("unknown DERP region: " + std::string(value));
}

int run_genkey(const std::vector<std::string>& args) {
  std::string path;
  std::string region_arg;
  bool use_psk = true;
  bool force = false;

  for (std::size_t i = 0; i < args.size(); ++i) {
    const auto& arg = args[i];
    if (arg == "--key") {
      if (++i >= args.size()) throw std::invalid_argument("--key requires a path");
      path = args[i];
    } else if (arg.rfind("--key=", 0) == 0) {
      path = arg.substr(6U);
    } else if (arg == "--region") {
      if (++i >= args.size()) throw std::invalid_argument("--region requires a value");
      region_arg = args[i];
    } else if (arg.rfind("--region=", 0) == 0) {
      region_arg = arg.substr(9U);
    } else if (arg == "--psk=false") {
      use_psk = false;
    } else if (arg == "--psk=true") {
      use_psk = true;
    } else if (arg == "--force") {
      force = true;
    } else {
      throw std::invalid_argument("unsupported genkey option: " + arg);
    }
  }

  if (path.empty() || path == "new") {
    throw std::invalid_argument("genkey requires --key=<file>");
  }
  if (std::filesystem::exists(path) && !force) {
    throw std::runtime_error("key file already exists; use --force to replace it: " + path);
  }

  const auto map = fetch_derp_map();
  const auto region_id = resolve_region_argument(region_arg, map);
  auto saved = new_saved_tailcat_key(use_psk, region_id);
  save_tailcat_key(path, saved);

  ConnInfo info;
  info.server_public = saved.identity.public_key;
  info.server_disco_public = derive_disco_key(saved.identity.private_key).public_key;
  info.preshared_key = saved.preshared_key;
  info.region_id = saved.region_id;
  std::cout << encode_tailcat_addr(info) << '\n';
  std::cerr << "# saved Tailcat identity to " << path << '\n';
  return 0;
}

}  // namespace

std::optional<int> run_extra_command(std::string_view command,
                                     const std::vector<std::string>& args,
                                     bool verbose) {
  if (command == "cp") return run_scp_command(args, verbose);
  if (command == "browse") return run_browse_command(args, verbose);
  if (command == "resolve") return run_resolve(args);
  if (command == "genkey") return run_genkey(args);
  return std::nullopt;
}

}  // namespace tailcat
