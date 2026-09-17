// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/ip.hpp"

#include <algorithm>

namespace tailcat {

Ip6Address tailcat_ip_for_node(const Key32& node_public) noexcept {
  Ip6Address out{};
  out[0] = 0xfdU;
  out[1] = 0x7aU;
  out[2] = 0x11U;
  out[3] = 0x5cU;
  out[4] = 0xa1U;
  out[5] = 0xe0U;
  std::copy_n(node_public.begin(), 10, out.begin() + 6);
  return out;
}

}  // namespace tailcat
