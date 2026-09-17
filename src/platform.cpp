// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/platform.hpp"

#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#endif

namespace tailcat {

std::string platform_name() {
#ifdef _WIN32
  return "windows";
#elif defined(__APPLE__)
  return "macos";
#elif defined(__linux__)
  return "linux";
#else
  return "unknown";
#endif
}

void initialize_platform() {
#ifdef _WIN32
  WSADATA data{};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
    throw std::runtime_error("WSAStartup failed");
  }
#endif
}

void shutdown_platform() noexcept {
#ifdef _WIN32
  WSACleanup();
#endif
}

}  // namespace tailcat
