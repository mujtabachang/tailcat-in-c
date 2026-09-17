// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/cli.hpp"
#include "tailcat/platform.hpp"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace tailcat {
namespace {

constexpr std::string_view kVersion = "0.1.0-cpp";

bool is_help(std::string_view arg) { return arg == "-h" || arg == "--help"; }
bool is_version(std::string_view arg) { return arg == "-V" || arg == "--version" || arg == "version"; }

int unavailable(std::string_view command) {
  std::cerr << "tailcat: '" << command
            << "' is part of the native C++ rewrite but its data-plane implementation is not yet enabled.\n"
            << "The repository intentionally contains no Go fallback.\n";
  return 2;
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
      << "  tailcat [options]                 Listen for a pipe connection\n"
      << "  tailcat <tc-address> [port]       Connect to a peer\n"
      << "  tailcat serve ...                 Serve ports/files/SSH/exec\n"
      << "  tailcat forward ...               Forward local ports\n"
      << "  tailcat browse ...                Open a forwarded HTTP service\n"
      << "  tailcat cp ...                    Copy files\n"
      << "  tailcat recv ...                  Receive files\n"
      << "  tailcat ssh ...                   SSH through tailcat\n"
      << "  tailcat socks ...                 Run a SOCKS proxy\n"
      << "  tailcat ping ...                  Probe a peer\n"
      << "  tailcat genkey ...                Generate reusable connection material\n"
      << "  tailcat parse ...                 Decode a tailcat address\n\n"
      << "Options:\n"
      << "  -h, --help       Show this help\n"
      << "  -V, --version    Show version\n"
      << "  -v, --verbose    Enable diagnostic logging\n";
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

  static const std::unordered_set<std::string> commands = {
      "serve", "forward", "browse", "cp", "recv", "ssh", "socks", "ping", "genkey", "parse", "ls"};

  if (cli.command.empty()) {
    return unavailable("listen");
  }
  if (commands.contains(cli.command)) {
    return unavailable(cli.command);
  }
  if (cli.command.rfind("tc", 0) == 0) {
    return unavailable("connect");
  }

  std::cerr << "tailcat: unknown command or address: " << cli.command << "\n\n" << usage();
  return 2;
}

}  // namespace tailcat
