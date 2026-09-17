#include "tailcat/wireguard_compat.h"

extern "C" {
#include "wireguard-platform.h"
}

#include <sodium.h>

#include <chrono>
#include <cstdint>
#include <mutex>

extern "C" uint32_t wireguard_sys_now() {
  using Clock = std::chrono::steady_clock;
  static const auto started = Clock::now();
  const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
  return static_cast<uint32_t>(static_cast<uint64_t>(millis) & 0xffffffffULL);
}

extern "C" void wireguard_random_bytes(void *bytes, size_t size) {
  randombytes_buf(bytes, size);
}

extern "C" void wireguard_tai64n_now(uint8_t *output) {
  using Clock = std::chrono::system_clock;
  constexpr uint64_t tai64_base = 0x400000000000000aULL;
  static std::mutex mutex;
  static uint64_t last_ns = 0;

  const auto since_epoch = Clock::now().time_since_epoch();
  auto ns_signed = std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch).count();
  uint64_t unix_ns = ns_signed > 0 ? static_cast<uint64_t>(ns_signed) : 0U;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (unix_ns <= last_ns) unix_ns = last_ns + 1U;
    last_ns = unix_ns;
  }

  const uint64_t seconds = tai64_base + unix_ns / 1000000000ULL;
  const uint32_t nanos = static_cast<uint32_t>(unix_ns % 1000000000ULL);
  for (int i = 0; i < 8; ++i) {
    output[i] = static_cast<uint8_t>(seconds >> static_cast<unsigned>((7 - i) * 8));
  }
  for (int i = 0; i < 4; ++i) {
    output[8 + i] = static_cast<uint8_t>(nanos >> static_cast<unsigned>((3 - i) * 8));
  }
}

extern "C" bool wireguard_is_under_load() {
  // WireGuard's cookie mechanism is optional DoS mitigation. DERP already
  // authenticates and rate-limits relay clients; the native engine still
  // validates MAC1 on every handshake and can add load-triggered cookies later.
  return false;
}
