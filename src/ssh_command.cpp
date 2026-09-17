// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/ssh_command.hpp"

#include "tailcat/protocol.hpp"

#include <sodium.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <process.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <limits.h>
#include <unistd.h>
#endif

namespace tailcat {
namespace {

std::string current_executable_path() {
#ifdef _WIN32
  std::vector<char> buffer(32768U, '\0');
  const auto length = GetModuleFileNameA(nullptr, buffer.data(),
                                         static_cast<DWORD>(buffer.size()));
  if (length == 0U || static_cast<std::size_t>(length) >= buffer.size()) {
    throw std::runtime_error("GetModuleFileName failed");
  }
  return std::string(buffer.data(), static_cast<std::size_t>(length));
#elif defined(__APPLE__)
  std::uint32_t size = 0;
  (void)_NSGetExecutablePath(nullptr, &size);
  std::vector<char> buffer(static_cast<std::size_t>(size) + 1U, '\0');
  if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
    throw std::runtime_error("_NSGetExecutablePath failed");
  }
  return std::string(buffer.data());
#else
  std::array<char, PATH_MAX + 1> buffer{};
  const auto length = readlink("/proc/self/exe", buffer.data(), PATH_MAX);
  if (length < 0) {
    throw std::runtime_error(std::string("readlink(/proc/self/exe): ") +
                             std::strerror(errno));
  }
  buffer[static_cast<std::size_t>(length)] = '\0';
  return std::string(buffer.data(), static_cast<std::size_t>(length));
#endif
}

bool has_control(std::string_view value) {
  for (const char c : value) {
    if (c == '\0' || c == '\r' || c == '\n') return true;
  }
  return false;
}

std::string unix_shell_quote(std::string_view value) {
  if (has_control(value)) {
    throw std::invalid_argument(
        "ProxyCommand argument contains a control character");
  }
  std::string escaped;
  escaped.reserve(value.size() + 8U);
  escaped.push_back('\'');
  for (const char c : value) {
    if (c == '%') {
      escaped += "%%";
    } else if (c == '\'') {
      escaped += "'\"'\"'";
    } else {
      escaped.push_back(c);
    }
  }
  escaped.push_back('\'');
  return escaped;
}

#ifdef _WIN32
std::string windows_arg_quote(std::string_view value) {
  if (has_control(value) ||
      value.find_first_of("\"%!") != std::string_view::npos) {
    throw std::invalid_argument("ProxyCommand argument is unsafe for cmd.exe");
  }
  std::string out;
  out.push_back('"');
  std::size_t slash_run = 0U;
  for (const char c : value) {
    if (c == '\\') {
      ++slash_run;
      out.push_back(c);
    } else {
      slash_run = 0U;
      out.push_back(c);
    }
  }
  out.append(slash_run, '\\');
  out.push_back('"');
  return out;
}
#endif

std::uint16_t parse_ssh_port(std::string_view text) {
  if (text.empty()) throw std::invalid_argument("SSH port is empty");
  std::size_t consumed = 0U;
  const auto value = std::stoul(std::string(text), &consumed, 10);
  if (consumed != text.size() || value == 0U || value > 65535U) {
    throw std::invalid_argument("invalid SSH port: " + std::string(text));
  }
  return static_cast<std::uint16_t>(value);
}

struct ParsedSshArgs {
  std::string port = "22";
  std::string destination;
  std::vector<std::string> ssh_tail;
};

ParsedSshArgs parse_ssh_args(const std::vector<std::string>& args) {
  ParsedSshArgs out;
  bool options = true;
  std::size_t i = 0U;
  for (; i < args.size(); ++i) {
    const auto& arg = args[i];
    if (options && arg == "--") {
      options = false;
      continue;
    }
    if (options && (arg == "-p" || arg == "--port")) {
      if (++i >= args.size()) {
        throw std::invalid_argument(arg + " requires a value");
      }
      out.port = args[i];
      continue;
    }
    if (options && arg.rfind("-p", 0) == 0 && arg.size() > 2U) {
      out.port = arg.substr(2U);
      continue;
    }
    if (options && arg.rfind("--port=", 0) == 0) {
      out.port = arg.substr(7U);
      continue;
    }
    if (options && arg == "--skip-dns-safety-check") {
      continue;
    }
    out.destination = arg;
    ++i;
    break;
  }
  if (out.destination.empty()) {
    throw std::invalid_argument("ssh requires [user@]<tc-address>");
  }
  (void)parse_ssh_port(out.port);
  out.ssh_tail.assign(args.begin() + static_cast<std::ptrdiff_t>(i), args.end());
  return out;
}

int exec_program(std::string_view program, const std::vector<std::string>& args) {
#ifdef _WIN32
  std::vector<const char*> argv;
  argv.reserve(args.size() + 1U);
  for (const auto& arg : args) argv.push_back(arg.c_str());
  argv.push_back(nullptr);
  const auto rc = _spawnvp(_P_WAIT, std::string(program).c_str(), argv.data());
  if (rc == -1) {
    throw std::runtime_error("failed to run " + std::string(program) +
                             ": " + std::strerror(errno));
  }
  return static_cast<int>(rc);
#else
  std::vector<char*> argv;
  argv.reserve(args.size() + 1U);
  for (const auto& arg : args) {
    argv.push_back(const_cast<char*>(arg.c_str()));
  }
  argv.push_back(nullptr);
  execvp(std::string(program).c_str(), argv.data());
  throw std::runtime_error("failed to exec " + std::string(program) +
                           ": " + std::strerror(errno));
#endif
}

struct RemoteSpec {
  std::string user;
  std::string address;
  std::string path;
};

std::optional<RemoteSpec> parse_tailcat_remote(std::string_view operand) {
  const auto colon = operand.find(':');
  if (colon == std::string_view::npos) return std::nullopt;
  std::string host(operand.substr(0U, colon));
  RemoteSpec out;
  const auto at = host.find('@');
  if (at != std::string::npos) {
    out.user = host.substr(0U, at);
    host.erase(0U, at + 1U);
  }
  if (host.rfind("tc", 0) != 0) return std::nullopt;
  (void)parse_tailcat_addr(host);
  out.address = std::move(host);
  out.path = std::string(operand.substr(colon + 1U));
  return out;
}

std::vector<std::string> ssh_transport_options(const std::string& proxy) {
  return {
      "-o", "UpdateHostKeys no",
      "-o", "StrictHostKeyChecking no",
#ifdef _WIN32
      "-o", "UserKnownHostsFile NUL",
#else
      "-o", "UserKnownHostsFile /dev/null",
#endif
      "-o", "LogLevel ERROR",
      "-o", "ProxyCommand=" + proxy,
  };
}

}  // namespace

std::string ssh_destination_host(std::string_view address) {
  std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
  if (crypto_hash_sha256(digest.data(),
                         reinterpret_cast<const unsigned char*>(address.data()),
                         static_cast<unsigned long long>(address.size())) != 0) {
    throw std::runtime_error("SHA-256 failed");
  }
  std::ostringstream out;
  out << "tailcat-" << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < 8U; ++i) {
    out << std::setw(2) << static_cast<unsigned>(digest[i]);
  }
  return out.str();
}

std::string ssh_proxy_command(std::string_view executable,
                              std::string_view address,
                              std::string_view port,
                              bool verbose) {
  std::vector<std::string> parts;
  parts.emplace_back(executable);
  if (verbose) parts.emplace_back("--verbose");
  parts.emplace_back(address);
  parts.emplace_back(port);

  std::ostringstream out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i != 0U) out << ' ';
#ifdef _WIN32
    out << windows_arg_quote(parts[i]);
#else
    out << unix_shell_quote(parts[i]);
#endif
  }
  return out.str();
}

int run_ssh_command(const std::vector<std::string>& args, bool verbose) {
  const auto parsed = parse_ssh_args(args);

  std::string user;
  std::string address = parsed.destination;
  const auto at = address.find('@');
  if (at != std::string::npos) {
    user = address.substr(0U, at);
    address.erase(0U, at + 1U);
  }
  if (address.rfind("tc", 0) != 0) {
    throw std::invalid_argument(
        "native tailcat ssh currently requires a tc... address");
  }
  (void)parse_tailcat_addr(address);

  const auto proxy = ssh_proxy_command(current_executable_path(), address,
                                       parsed.port, verbose);
  std::string destination = ssh_destination_host(address);
  if (!user.empty()) destination = user + "@" + destination;

  std::vector<std::string> ssh_args = {"ssh"};
  const auto options = ssh_transport_options(proxy);
  ssh_args.insert(ssh_args.end(), options.begin(), options.end());
  ssh_args.push_back("--");
  ssh_args.push_back(destination);
  ssh_args.insert(ssh_args.end(), parsed.ssh_tail.begin(), parsed.ssh_tail.end());
  return exec_program("ssh", ssh_args);
}

int run_scp_command(const std::vector<std::string>& args, bool verbose) {
  if (args.size() < 2U) {
    throw std::invalid_argument("cp requires a source and destination");
  }

  std::string port = "22";
  std::optional<RemoteSpec> remote;
  std::vector<std::string> operands;
  operands.reserve(args.size());

  for (std::size_t i = 0; i < args.size(); ++i) {
    const auto& arg = args[i];
    if (arg == "-P") {
      if (++i >= args.size()) throw std::invalid_argument("-P requires a port");
      port = args[i];
      (void)parse_ssh_port(port);
      continue;
    }
    if (arg.rfind("-P", 0) == 0 && arg.size() > 2U) {
      port = arg.substr(2U);
      (void)parse_ssh_port(port);
      continue;
    }

    const auto candidate = parse_tailcat_remote(arg);
    if (!candidate) {
      operands.push_back(arg);
      continue;
    }
    if (remote) {
      throw std::invalid_argument(
          "cp currently supports exactly one Tailcat remote operand");
    }
    remote = *candidate;
    std::string rewritten;
    if (!candidate->user.empty()) rewritten = candidate->user + "@";
    rewritten += ssh_destination_host(candidate->address);
    rewritten.push_back(':');
    rewritten += candidate->path;
    operands.push_back(std::move(rewritten));
  }

  if (!remote) {
    throw std::invalid_argument(
        "cp requires one remote operand of the form [user@]tc...:path");
  }

  const auto proxy = ssh_proxy_command(current_executable_path(), remote->address,
                                       port, verbose);
  std::vector<std::string> scp_args = {"scp"};
  const auto options = ssh_transport_options(proxy);
  scp_args.insert(scp_args.end(), options.begin(), options.end());
  scp_args.insert(scp_args.end(), operands.begin(), operands.end());
  return exec_program("scp", scp_args);
}

}  // namespace tailcat
