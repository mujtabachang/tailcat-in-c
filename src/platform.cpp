// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/platform.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#else
#include <sys/types.h>
#include <unistd.h>
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

void prepare_binary_stdio() {
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
    throw std::runtime_error("failed to put stdin in binary mode");
  }
  if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
    throw std::runtime_error("failed to put stdout in binary mode");
  }
#endif
}

std::vector<std::uint8_t> read_stdin_some(std::size_t max_bytes) {
  if (max_bytes == 0U) return {};
  max_bytes = std::min(max_bytes, static_cast<std::size_t>(INT_MAX));
  std::vector<std::uint8_t> out(max_bytes);
  for (;;) {
#ifdef _WIN32
    const int count = _read(_fileno(stdin), out.data(), static_cast<unsigned>(max_bytes));
    if (count < 0) {
#else
    const auto count = ::read(STDIN_FILENO, out.data(), max_bytes);
    if (count < 0) {
#endif
      if (errno == EINTR) continue;
      throw std::runtime_error(std::string("stdin read failed: ") + std::strerror(errno));
    }
    if (count == 0) return {};
    out.resize(static_cast<std::size_t>(count));
    return out;
  }
}

void write_stdout_all(std::span<const std::uint8_t> data) {
  std::size_t offset = 0U;
  while (offset < data.size()) {
    const auto amount = std::min(data.size() - offset,
                                 static_cast<std::size_t>(INT_MAX));
#ifdef _WIN32
    const int written = _write(_fileno(stdout), data.data() + offset,
                               static_cast<unsigned>(amount));
    if (written < 0) {
#else
    const auto written = ::write(STDOUT_FILENO, data.data() + offset, amount);
    if (written < 0) {
#endif
      if (errno == EINTR) continue;
      throw std::runtime_error(std::string("stdout write failed: ") + std::strerror(errno));
    }
    if (written == 0) throw std::runtime_error("stdout write returned zero bytes");
    offset += static_cast<std::size_t>(written);
  }
}

void open_system_url(const std::string& url) {
  if (url.empty()) throw std::invalid_argument("URL is empty");
#ifdef _WIN32
  const auto result = reinterpret_cast<std::intptr_t>(
      ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
  if (result <= 32) throw std::runtime_error("failed to open URL in default browser");
#else
  const pid_t pid = fork();
  if (pid < 0) throw std::runtime_error("fork failed while opening browser");
  if (pid == 0) {
#ifdef __APPLE__
    execlp("open", "open", url.c_str(), static_cast<char*>(nullptr));
#else
    execlp("xdg-open", "xdg-open", url.c_str(), static_cast<char*>(nullptr));
#endif
    _exit(127);
  }
#endif
}

}  // namespace tailcat
