// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/cli.hpp"

#include <cassert>
#include <string>

int main() {
  char a0[] = "tailcat";
  char a1[] = "--version";
  char* argv1[] = {a0, a1};
  auto v = tailcat::parse_command_line(2, argv1);
  assert(v.show_version);

  char b0[] = "tailcat";
  char b1[] = "serve";
  char b2[] = "8080";
  char* argv2[] = {b0, b1, b2};
  auto s = tailcat::parse_command_line(3, argv2);
  assert(s.command == "serve");
  assert(s.args.size() == 1);
  assert(s.args[0] == "8080");

  char c0[] = "tailcat";
  char c1[] = "--key=server.json";
  char c2[] = "serve";
  char c3[] = "ssh";
  char* argv3[] = {c0, c1, c2, c3};
  auto k = tailcat::parse_command_line(4, argv3);
  assert(k.key_path == "server.json");
  assert(k.command == "serve");
  assert(k.args.size() == 1U && k.args[0] == "ssh");

  // Once a subcommand is selected, option-looking arguments belong to it.
  char d0[] = "tailcat";
  char d1[] = "ssh";
  char d2[] = "tcabc";
  char d3[] = "--help";
  char* argv4[] = {d0, d1, d2, d3};
  auto remote = tailcat::parse_command_line(4, argv4);
  assert(!remote.show_help);
  assert(remote.command == "ssh");
  assert(remote.args.size() == 2U && remote.args[1] == "--help");

  assert(tailcat::usage().find("native C++20") != std::string::npos);
  assert(tailcat::usage().find("--key=PATH") != std::string::npos);
  return 0;
}
