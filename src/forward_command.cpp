// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/forward_command.hpp"

#include "tailcat/address_resolver.hpp"
#include "tailcat/crypto.hpp"
#include "tailcat/data_plane.hpp"
#include "tailcat/derp_http.hpp"
#include "tailcat/derp_map.hpp"
#include "tailcat/local_forward.hpp"
#include "tailcat/platform.hpp"
#include "tailcat/protocol.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tailcat {
namespace {

using namespace std::chrono_literals;
constexpr std::string_view kDefaultDerpMap = "https://tailcat.dev/derpmap.json";

std::uint16_t parse_forward_port(std::string_view text, bool allow_zero = false) {
  if (text.empty()) throw std::invalid_argument("empty forward port");
  std::size_t consumed = 0;
  const auto value = std::stoul(std::string(text), &consumed, 10);
  if (consumed != text.size() || value > 65535U || (!allow_zero && value == 0U)) {
    throw std::invalid_argument("invalid forward port: " + std::string(text));
  }
  return static_cast<std::uint16_t>(value);
}

TcpForwardMapping parse_mapping(std::string_view text) {
  const auto colon = text.find(':');
  if (colon == std::string_view::npos) {
    const auto port = parse_forward_port(text);
    return TcpForwardMapping{port, port};
  }
  if (colon == 0U || colon + 1U >= text.size() ||
      text.find(':', colon + 1U) != std::string_view::npos) {
    throw std::invalid_argument("invalid forward mapping: " + std::string(text));
  }
  return TcpForwardMapping{parse_forward_port(text.substr(0U, colon), true),
                           parse_forward_port(text.substr(colon + 1U))};
}

DerpRegion resolve_forward_region(const ConnInfo& info) {
  if (!info.regions.empty()) {
    if (info.region_id != 0) {
      for (const auto& region : info.regions) {
        if (region.region_id == info.region_id) return region;
      }
    }
    return info.regions.front();
  }
  if (info.region_id == 0) {
    throw std::runtime_error("tailcat address contains no DERP region");
  }
  return region_by_id(fetch_derp_map(std::string(kDefaultDerpMap)), info.region_id);
}

int run_forward_loop(std::string address_argument, std::string bind_address,
                     std::vector<TcpForwardMapping> mappings, bool verbose,
                     bool open_browser) {
  const auto resolved = resolve_tailcat_address_argument(address_argument);
  const auto address = resolved.address;
  auto info = parse_tailcat_addr(address);
  const auto region = resolve_forward_region(info);
  const auto node = primary_derp_node(region);
  const auto identity = generate_node_key();

  if (verbose) {
    if (resolved.via_dns) {
      std::cerr << "# resolved " << resolved.dns_name << " via tailcat= TXT\n";
    }
    std::cerr << "# connecting forwarder through DERP region " << region.region_id;
    if (!region.region_code.empty()) std::cerr << " (" << region.region_code << ')';
    std::cerr << '\n';
  }

  DerpHttpClient derp(node, identity, "tailcat");
  derp.connect();
  TailcatClientDataPlane data(derp, identity, std::move(info));
  data.connect(15s);
  LocalTcpForwarder forwarder(data, std::move(mappings), bind_address);

  for (const auto& mapping : forwarder.mappings()) {
    std::cerr << "# forwarding " << bind_address << ':' << mapping.local_port
              << " -> tailcat:" << mapping.remote_port << '\n';
  }

  if (open_browser) {
    if (forwarder.mappings().size() != 1U) {
      throw std::runtime_error("browse requires exactly one forward mapping");
    }
    const auto port = forwarder.mappings().front().local_port;
    const auto url = std::string("http://127.0.0.1:") + std::to_string(port) + "/";
    std::cerr << "# opening " << url << '\n';
    open_system_url(url);
  }

  for (;;) {
    (void)data.pump_for(10ms);
    forwarder.poll();
  }
}

}  // namespace

int run_forward_command(const std::vector<std::string>& args, bool verbose) {
  std::string bind_address = "127.0.0.1";
  std::string address;
  std::vector<TcpForwardMapping> mappings;

  for (const auto& arg : args) {
    constexpr std::string_view prefix = "--bind=";
    if (arg.rfind(prefix, 0) == 0) {
      bind_address = arg.substr(prefix.size());
      if (bind_address.empty()) {
        throw std::invalid_argument("--bind requires an address");
      }
      continue;
    }
    if (!arg.empty() && arg[0] == '-') {
      throw std::invalid_argument("unsupported forward option: " + arg);
    }
    if (address.empty()) {
      address = arg;
    } else {
      mappings.push_back(parse_mapping(arg));
    }
  }

  if (address.empty()) {
    throw std::invalid_argument("forward requires a <tc-address-or-dns-name>");
  }
  if (mappings.empty()) {
    throw std::invalid_argument(
        "forward requires one or more [local:]remote port mappings");
  }
  return run_forward_loop(std::move(address), std::move(bind_address),
                          std::move(mappings), verbose, false);
}

int run_browse_command(const std::vector<std::string>& args, bool verbose) {
  if (args.empty() || args.size() > 2U) {
    throw std::invalid_argument("browse requires <tc-address-or-dns-name> [remote-port]");
  }
  const auto remote_port = args.size() == 2U
                               ? parse_forward_port(args[1])
                               : static_cast<std::uint16_t>(80U);
  std::vector<TcpForwardMapping> mappings;
  mappings.push_back(TcpForwardMapping{0U, remote_port});
  return run_forward_loop(args[0], "127.0.0.1", std::move(mappings), verbose,
                          true);
}

}  // namespace tailcat
