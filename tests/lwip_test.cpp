// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

extern "C" {
#include "lwip/init.h"
#include "lwip/sys.h"
}

#include <cassert>
#include <cstdint>

int main() {
  lwip_init();
  const std::uint32_t before = sys_now();
  const std::uint32_t after = sys_now();
  assert(after >= before);
  return 0;
}
