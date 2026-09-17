// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <string>
#include <vector>

namespace tailcat {

int run_forward_command(const std::vector<std::string>& args, bool verbose);
int run_browse_command(const std::vector<std::string>& args, bool verbose);

}  // namespace tailcat
