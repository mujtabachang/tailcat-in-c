// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <string>

namespace tailcat {

std::string platform_name();
void initialize_platform();
void shutdown_platform() noexcept;

}  // namespace tailcat
