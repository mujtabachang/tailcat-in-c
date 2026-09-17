// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace tailcat {

// Runs the system OpenSSH client with Tailcat itself as ProxyCommand.
// On POSIX this replaces the current process; on Windows it waits for ssh.exe
// and returns its exit code.
int run_ssh_command(const std::vector<std::string>& args, bool verbose,
                    std::string_view key_name = {});

// Runs the system scp client with Tailcat itself as ProxyCommand. Exactly one
// remote operand must name a tc... address.
int run_scp_command(const std::vector<std::string>& args, bool verbose,
                    std::string_view key_name = {});

// Exposed for hermetic tests and for scp/cp command construction.
std::string ssh_proxy_command(std::string_view executable,
                              std::string_view address,
                              std::string_view port,
                              bool verbose,
                              std::string_view key_name = {});
std::string ssh_destination_host(std::string_view address);

}  // namespace tailcat
