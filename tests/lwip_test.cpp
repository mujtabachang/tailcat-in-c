// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

extern "C" {
#include "lwip/init.h"
#include "lwip/ip6_frag.h"
#include "lwip/sys.h"
}

#include <cassert>
#include <cstdint>

static_assert(IPV6_FRAG_COPYHEADER == 1,
              "64-bit Tailcat builds must copy IPv6 fragment headers");

int main() {
  lwip_init();
  const std::uint32_t before = sys_now();
  ip6_reass_tmr();
  const std::uint32_t after = sys_now();
  assert(after >= before);
  return 0;
}
