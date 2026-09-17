// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/extra_commands.hpp"

#include "tailcat/ssh_command.hpp"

namespace tailcat {

std::optional<int> run_extra_command(std::string_view command,
                                     const std::vector<std::string>& args,
                                     bool verbose) {
  if (command == "cp") return run_scp_command(args, verbose);
  return std::nullopt;
}

}  // namespace tailcat
