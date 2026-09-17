// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace tailcat {

struct CommandLine {
  bool show_help = false;
  bool show_version = false;
  bool verbose = false;
  std::string key_path;
  std::string command;
  std::vector<std::string> args;
};

CommandLine parse_command_line(int argc, char** argv);
std::string usage();
int run(const CommandLine& cli);

}  // namespace tailcat
