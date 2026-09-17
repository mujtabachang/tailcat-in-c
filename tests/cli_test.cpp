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
  assert(tailcat::usage().find("native C++20") != std::string::npos);
  return 0;
}
