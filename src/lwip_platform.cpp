// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include <sodium.h>

#include <chrono>
#include <cstdint>

extern "C" std::uint32_t sys_now(void) {
  using Clock = std::chrono::steady_clock;
  static const auto started = Clock::now();
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      Clock::now() - started).count();
  return static_cast<std::uint32_t>(static_cast<std::uint64_t>(elapsed) & 0xffffffffULL);
}

extern "C" unsigned int tailcat_lwip_rand(void) {
  if (sodium_init() < 0) return 0U;
  return randombytes_random();
}
