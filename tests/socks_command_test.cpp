// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/socks_command.hpp"

#include <cassert>
#include <stdexcept>
#include <string>

namespace {

void expect(std::string input, std::string host, std::uint16_t port) {
  const auto got = tailcat::parse_socks_listen_address(input);
  assert(got.host == host);
  assert(got.port == port);
}

}  // namespace

int main() {
  expect("1234", "127.0.0.1", 1234U);
  expect(":1234", "", 1234U);
  expect("127.0.0.1", "127.0.0.1", 0U);
  expect("[2001:db8::1]", "2001:db8::1", 0U);
  expect("[2001:db8::1]:1080", "2001:db8::1", 1080U);
  expect("2001:db8::1", "2001:db8::1", 0U);
  expect("foo", "foo", 0U);

  bool bad_port = false;
  try {
    (void)tailcat::parse_socks_listen_address("127.0.0.1:99999");
  } catch (const std::invalid_argument&) {
    bad_port = true;
  }
  assert(bad_port);

  bool bad_brackets = false;
  try {
    (void)tailcat::parse_socks_listen_address("[2001:db8::1");
  } catch (const std::invalid_argument&) {
    bad_brackets = true;
  }
  assert(bad_brackets);
  return 0;
}
