// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/cli.hpp"
#include "tailcat/transport.hpp"

#include <cassert>
#include <stdexcept>
#include <string>

int main() {
  char a0[] = "tailcat";
  char a1[] = "--version";
  char* argv1[] = {a0, a1};
  auto v = tailcat::parse_command_line(2, argv1);
  assert(v.show_version);

  char b0[] = "tailcat";
  char b1[] = "serve";
  char b2[] = "8080";
  char* argv2[] = {b0, b1, b2};
  auto s = tailcat::parse_command_line(3, argv2);
  assert(s.command == "serve");
  assert(s.args.size() == 1);
  assert(s.args[0] == "8080");

  char c0[] = "tailcat";
  char c1[] = "--bind=127.0.0.1";
  char c2[] = "--port=0";
  char* argv3[] = {c0, c1, c2};
  auto listen = tailcat::parse_command_line(3, argv3);
  assert(listen.command.empty());
  assert(listen.args.size() == 2);

  const auto ipv4 = tailcat::parse_tcp_endpoint("tcp://127.0.0.1:4567");
  assert(ipv4.host == "127.0.0.1");
  assert(ipv4.port == 4567);
  assert(tailcat::format_tcp_endpoint(ipv4) == "tcp://127.0.0.1:4567");

  const auto ipv6 = tailcat::parse_tcp_endpoint("tcp://[::1]:8080");
  assert(ipv6.host == "::1");
  assert(ipv6.port == 8080);
  assert(tailcat::format_tcp_endpoint(ipv6) == "tcp://[::1]:8080");

  bool rejected = false;
  try {
    (void)tailcat::parse_tcp_endpoint("tc-not-a-tcp-endpoint");
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  assert(rejected);

  assert(tailcat::usage().find("native C++20") != std::string::npos);
  assert(tailcat::usage().find("tcp://HOST:PORT") != std::string::npos);
  return 0;
}
