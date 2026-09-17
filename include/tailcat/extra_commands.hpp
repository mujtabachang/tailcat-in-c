// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tailcat {

// Returns std::nullopt when command is not handled here.
std::optional<int> run_extra_command(std::string_view command,
                                     const std::vector<std::string>& args,
                                     bool verbose,
                                     std::string_view key_name = {});

}  // namespace tailcat
