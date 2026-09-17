// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace tailcat {

std::string platform_name();
void initialize_platform();
void shutdown_platform() noexcept;

// Raw byte-stream helpers used by netcat/ProxyCommand mode. On Windows these
// switch stdin/stdout to binary mode so SSH and file protocols are not altered
// by CRLF or Ctrl-Z text processing.
void prepare_binary_stdio();
std::vector<std::uint8_t> read_stdin_some(std::size_t max_bytes = 16U * 1024U);
void write_stdout_all(std::span<const std::uint8_t> data);

}  // namespace tailcat
