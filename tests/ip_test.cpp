// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/ip.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>

int main() {
  tailcat::Key32 key{};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<std::uint8_t>(i);
  }

  const auto ip = tailcat::tailcat_ip_for_node(key);
  const tailcat::Ip6Address want{
      0xfdU, 0x7aU, 0x11U, 0x5cU, 0xa1U, 0xe0U,
      0x00U, 0x01U, 0x02U, 0x03U, 0x04U,
      0x05U, 0x06U, 0x07U, 0x08U, 0x09U};
  assert(ip == want);
  return 0;
}
