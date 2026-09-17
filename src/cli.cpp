// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/cli.hpp"
#include "tailcat/platform.hpp"
#include "tailcat/transport.hpp"

#include <charconv>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

#ifndef TAILCAT_VERSION
#define TAILCAT_VERSION "0.1.0"
#endif

namespace tailcat {
namespace {

constexpr std::string_view kVersion = TAILCAT_VERSION;

bool is_help(std::string_view arg) { return arg == "-h" || arg == "--help"; }
bool is_version(std::string_view arg) { return arg == "-V" || arg == "--version" || arg == "version"; }

int unavailable(std::string_view command) {
  std::cerr << "tailcat: '" << command
            << "' is part of the native C++ rewrite but its DERP/WireGuard data-plane implementation is not yet enabled.\n"
            << "Use the native tcp:// bootstrap transport for stdin/stdout piping in the meantime.\n";
  return 2;
}

std::uint16_t parse_listen_port(std::string_view value) {
  unsigned int parsed = 0;
  const auto [ptr, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (error != std::errc{} || ptr != value.data() + value.size() || parsed > 65535U) {
    throw std::invalid_argument("invalid listen port: " + std::string(value));
  }
  return static_cast<std::uint16_t>(parsed);
}

int run_listener(const std::vector<std::string>& args) {
  std::string bind_host = "0.0.0.0";
  std::uint16_t port = 0;

  for (const std::string& arg : args) {
    constexpr std::string_view bind_prefix = "--bind=";
    constexpr std::string_view port_prefix = "--port=";
    if (std::string_view(arg).starts_with(bind_prefix)) {
      bind_host = arg.substr(bind_prefix.size());
      if (bind_host.empty()) {
        throw std::invalid_argument("--bind requires an address");
      }
      continue;
    }
    if (std::string_view(arg).starts_with(port_prefix)) {
      port = parse_listen_port(std::string_view(arg).substr(port_prefix.size()));
      continue;
    }
    throw std::invalid_argument("unknown listen option: " + arg);
  }

  return run_tcp_listener(bind_host, port);
}

}  // namespace

CommandLine parse_command_line(int argc, char** argv) {
  CommandLine out;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (is_help(arg)) {
      out.show_help = true;
      continue;
    }
    if (is_version(arg)) {
      out.show_version = true;
      continue;
    }
    if (arg == "-v" || arg == "--verbose") {
      out.verbose = true;
      continue;
    }
    if (out.command.empty() && !arg.empty() && arg[0] != '-') {
      out.command = arg;
    } else {
      out.args.push_back(arg);
    }
  }
  return out;
}

std::string usage() {
  std::ostringstream out;
  out << "tailcat " << kVersion << " (native C++20)\n\n"
      << "Usage:\n"
      << "  tailcat [--bind=ADDR] [--port=N]  Listen using the native TCP bootstrap transport\n"
      << "  tailcat listen [options]          Same as above\n"
      << "  tailcat tcp://HOST:PORT           Connect and pipe stdin/stdout over native TCP\n"
      << "  tailcat <tc-address> [port]       Reserved for DERP/WireGuard-compatible Tailcat transport\n"
      << "  tailcat serve ...                 Serve ports/files/SSH/exec (planned)\n"
      << "  tailcat forward ...               Forward local ports (planned)\n"
      << "  tailcat browse ...                Open a forwarded HTTP service (planned)\n"
      << "  tailcat cp ...                    Copy files (planned)\n"
      << "  tailcat recv ...                  Receive files (planned)\n"
      << "  tailcat ssh ...                   SSH through tailcat (planned)\n"
      << "  tailcat socks ...                 Run a SOCKS proxy (planned)\n"
      << "  tailcat ping ...                  Probe a peer (planned)\n"
      << "  tailcat genkey ...                Generate reusable connection material (planned)\n"
      << "  tailcat parse ...                 Decode a tailcat address (planned)\n\n"
      << "Options:\n"
      << "  -h, --help       Show this help\n"
      << "  -V, --version    Show version\n"
      << "  -v, --verbose    Enable diagnostic logging\n\n"
      << "Native TCP bootstrap mode is not encrypted and is not compatible with upstream tc... addresses.\n";
  return out.str();
}

int run(const CommandLine& cli) {
  if (cli.show_version) {
    std::cout << "tailcat " << kVersion << " (" << platform_name() << ")\n";
    return 0;
  }
  if (cli.show_help) {
    std::cout << usage();
    return 0;
  }

  if (cli.command.empty()) {
    return run_listener(cli.args);
  }
  if (cli.command == "listen") {
    return run_listener(cli.args);
  }
  if (std::string_view(cli.command).starts_with("tcp://")) {
    if (!cli.args.empty()) {
      throw std::invalid_argument("tcp:// connection does not accept additional arguments");
    }
    return run_tcp_client(parse_tcp_endpoint(cli.command));
  }
  if (std::string_view(cli.command).starts_with("tc")) {
    return unavailable("connect");
  }

  static const std::unordered_set<std::string> commands = {
      "serve", "forward", "browse", "cp", "recv", "ssh", "socks", "ping", "genkey", "parse", "ls"};
  if (commands.contains(cli.command)) {
    return unavailable(cli.command);
  }

  std::cerr << "tailcat: unknown command or address: " << cli.command << "\n\n" << usage();
  return 2;
}

}  // namespace tailcat
