// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/extra_commands.hpp"

#include "tailcat/crypto.hpp"
#include "tailcat/derp_map.hpp"
#include "tailcat/forward_command.hpp"
#include "tailcat/protocol.hpp"
#include "tailcat/saved_key.hpp"
#include "tailcat/socks_command.hpp"
#include "tailcat/ssh_command.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <optional>
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
  if (value.empty() || value == "auto") return select_derp_region(map).region_id;
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
    if (lower_ascii(region.region_code) == wanted ||
        lower_ascii(region.region_name) == wanted) {
      return region.region_id;
    }
  }
  throw std::invalid_argument("unknown DERP region: " + std::string(value));
}

int run_genkey(const std::vector<std::string>& args) {
  std::string key_name;
  std::string region_arg;
  bool use_psk = true;
  bool psk_was_set = false;
  bool force = false;
  bool client = false;
  bool list = false;
  bool remove = false;
  bool fixed_region = false;
  bool embed_derp_map = false;

  for (std::size_t i = 0; i < args.size(); ++i) {
    const auto& arg = args[i];
    if (arg == "--key") {
      if (++i >= args.size()) throw std::invalid_argument("--key requires a path or name");
      key_name = args[i];
    } else if (arg.rfind("--key=", 0) == 0) {
      key_name = arg.substr(6U);
    } else if (arg == "--region") {
      if (++i >= args.size()) throw std::invalid_argument("--region requires a value");
      region_arg = args[i];
    } else if (arg.rfind("--region=", 0) == 0) {
      region_arg = arg.substr(9U);
    } else if (arg == "--psk=false") {
      use_psk = false;
      psk_was_set = true;
    } else if (arg == "--psk=true") {
      use_psk = true;
      psk_was_set = true;
    } else if (arg == "--client") {
      client = true;
    } else if (arg == "--list") {
      list = true;
    } else if (arg == "--delete") {
      remove = true;
    } else if (arg == "--fixed-region") {
      fixed_region = true;
    } else if (arg == "--embed-derp-map") {
      embed_derp_map = true;
    } else if (arg == "--force") {
      force = true;
    } else {
      throw std::invalid_argument("unsupported genkey option: " + arg);
    }
  }

  if (list) {
    if (remove || client || !key_name.empty() || !region_arg.empty() || psk_was_set ||
        fixed_region || embed_derp_map) {
      throw std::invalid_argument("genkey --list cannot be combined with generation options");
    }
    for (const auto& name : list_saved_tailcat_keys()) std::cout << name << '\n';
    return 0;
  }

  if (remove) {
    if (key_name.empty() || key_name == "new") {
      throw std::invalid_argument("genkey --delete requires --key=<name-or-path>");
    }
    if (client || !region_arg.empty() || psk_was_set || fixed_region || embed_derp_map) {
      throw std::invalid_argument("genkey --delete cannot be combined with generation options");
    }
    const auto path = resolve_tailcat_key_path(key_name);
    delete_saved_tailcat_key(key_name);
    std::cerr << "# deleted Tailcat identity " << path << '\n';
    return 0;
  }

  if (key_name.empty() || key_name == "new") {
    throw std::invalid_argument("genkey requires --key=<name-or-path>");
  }
  if (client && key_name == "default") {
    throw std::invalid_argument(
        "genkey --client --key=default is ambiguous; use --key=client-default");
  }
  if (client && (!region_arg.empty() || fixed_region || embed_derp_map || psk_was_set)) {
    throw std::invalid_argument(
        "client keys do not take --region, --fixed-region, --embed-derp-map, or --psk");
  }

  const auto path = resolve_tailcat_key_path(key_name);
  if (std::filesystem::exists(path) && !force) {
    throw std::runtime_error("key file already exists; use --force to replace it: " + path);
  }

  if (client) {
    const auto saved = new_saved_tailcat_key(false, 0);
    save_tailcat_key(key_name, saved);
    std::cerr << "# wrote file to " << path << '\n';
    std::cout << node_public_text(saved.identity.public_key) << '\n';
    return 0;
  }

  const auto map = fetch_derp_map();
  const bool explicit_region = !region_arg.empty() && region_arg != "auto";
  const auto selected_region_id = resolve_region_argument(region_arg, map);
  const auto persisted_region_id =
      (explicit_region || fixed_region || embed_derp_map) ? selected_region_id : 0;
  const auto saved = new_saved_tailcat_key(use_psk, persisted_region_id);
  save_tailcat_key(key_name, saved);

  ConnInfo info;
  info.server_public = saved.identity.public_key;
  info.server_disco_public = derive_disco_key(saved.identity.private_key).public_key;
  info.preshared_key = saved.preshared_key;
  info.region_id = selected_region_id;
  if (embed_derp_map) info.regions.push_back(region_by_id(map, selected_region_id));

  std::cerr << "# wrote file to " << path << '\n';
  std::cout << encode_tailcat_addr(info) << '\n';
  return 0;
}

int run_printpub(std::string_view key_name) {
  NodeKeyPair identity;
  if (key_name == "new") {
    identity = generate_node_key();
  } else if (!key_name.empty()) {
    identity = load_saved_tailcat_key(std::string(key_name)).identity;
  } else if (saved_tailcat_key_exists("client-default")) {
    identity = load_saved_tailcat_key("client-default").identity;
  } else {
    identity = generate_node_key();
  }
  std::cout << node_public_text(identity.public_key) << '\n';
  return 0;
}

}  // namespace

std::optional<int> run_extra_command(std::string_view command,
                                     const std::vector<std::string>& args,
                                     bool verbose,
                                     std::string_view key_name) {
  if (command == "cp") return run_scp_command(args, verbose, key_name);
  if (command == "browse") return run_browse_command(args, verbose);
  if (command == "resolve") return run_resolve(args);
  if (command == "socks") return run_socks_command(args, verbose, key_name);
  if (command == "genkey") return run_genkey(args);
  if (command == "printpub") {
    if (!args.empty()) throw std::invalid_argument("printpub takes no positional arguments");
    return run_printpub(key_name);
  }
  return std::nullopt;
}

}  // namespace tailcat
