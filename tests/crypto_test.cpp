#include "tailcat/crypto.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

namespace {

tailcat::Key32 hex32(const char* s) {
  tailcat::Key32 out{};
  auto nybble = [](char c) -> std::uint8_t {
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
    assert(false);
    return 0;
  };
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>((nybble(s[i * 2]) << 4) | nybble(s[i * 2 + 1]));
  }
  return out;
}

}  // namespace

int main() {
  using namespace tailcat;
  initialize_crypto();

  const auto node_private = hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f");
  const auto want_node_public = hex32("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
  const auto want_disco_private = hex32("38a03eb943fbadb3bd1fa55af8589105509216a7619985ea7a15802e4d21f447");
  const auto want_disco_public = hex32("a0a9ef7d6f151e27b9dab235161d926c4101278caf73d0c751db5e87656beb7a");

  assert(node_public_from_private(node_private) == want_node_public);
  assert(derive_disco_private(node_private) == want_disco_private);
  assert(derive_disco_public(node_private) == want_disco_public);

  const auto alice = generate_node_keypair();
  const auto bob = generate_node_keypair();
  const std::string message = "tailcat DERP client info";
  const auto sealed = nacl_box_seal(
      alice.private_key,
      bob.public_key,
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
  const auto clear = nacl_box_open(bob.private_key, alice.public_key, sealed);
  assert(clear.has_value());
  assert(std::string(clear->begin(), clear->end()) == message);

  auto tampered = sealed;
  tampered.back() ^= 1;
  assert(!nacl_box_open(bob.private_key, alice.public_key, tampered).has_value());

  const auto psk = generate_preshared_key();
  bool any = false;
  for (auto b : psk) any = any || b != 0;
  assert(any);
  return 0;
}
