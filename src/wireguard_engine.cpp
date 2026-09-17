// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/wireguard_engine.hpp"
#include "tailcat/wireguard_compat.h"

extern "C" {
#include "wireguard.h"
}

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace tailcat {
namespace {

static_assert(sizeof(message_handshake_initiation) == 148U,
              "WireGuard initiation wire layout changed");
static_assert(sizeof(message_handshake_response) == 92U,
              "WireGuard response wire layout changed");
static_assert(sizeof(message_cookie_reply) == 64U,
              "WireGuard cookie wire layout changed");
static_assert(sizeof(message_transport_data) == 16U,
              "WireGuard transport header wire layout changed");

void initialize_wireguard_once() {
  static std::once_flag once;
  std::call_once(once, [] { wireguard_init(); });
}

std::uint32_t load_u32_le(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) |
         (static_cast<std::uint32_t>(p[1]) << 8U) |
         (static_cast<std::uint32_t>(p[2]) << 16U) |
         (static_cast<std::uint32_t>(p[3]) << 24U);
}

std::uint64_t load_u64_le(const std::uint8_t* p) {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8U; ++i) {
    value |= static_cast<std::uint64_t>(p[i]) << (i * 8U);
  }
  return value;
}

void store_u32_le(std::uint8_t* p, std::uint32_t value) {
  for (unsigned i = 0; i < 4U; ++i) {
    p[i] = static_cast<std::uint8_t>(value >> (i * 8U));
  }
}

void store_u64_le(std::uint8_t* p, std::uint64_t value) {
  for (unsigned i = 0; i < 8U; ++i) {
    p[i] = static_cast<std::uint8_t>(value >> (i * 8U));
  }
}

std::optional<std::size_t> inner_ip_length(std::span<const std::uint8_t> padded) {
  if (padded.empty()) return 0U;  // WireGuard keepalive.
  const auto version = static_cast<unsigned>(padded[0] >> 4U);
  if (version == 4U) {
    if (padded.size() < 20U) return std::nullopt;
    const auto ihl = static_cast<std::size_t>(padded[0] & 0x0fU) * 4U;
    const auto total = (static_cast<std::size_t>(padded[2]) << 8U) |
                       static_cast<std::size_t>(padded[3]);
    if (ihl < 20U || total < ihl || total > padded.size()) return std::nullopt;
    return total;
  }
  if (version == 6U) {
    if (padded.size() < 40U) return std::nullopt;
    const auto payload = (static_cast<std::size_t>(padded[4]) << 8U) |
                         static_cast<std::size_t>(padded[5]);
    const auto total = 40U + payload;
    if (total > padded.size()) return std::nullopt;
    return total;
  }
  return std::nullopt;
}

std::vector<std::uint8_t> bytes_of(const void* value, std::size_t size) {
  const auto* p = static_cast<const std::uint8_t*>(value);
  return std::vector<std::uint8_t>(p, p + size);
}

}  // namespace

struct WireGuardPeerEngine::Impl {
  NodeKeyPair local;
  Key32 remote{};
  std::optional<Key32> psk;
  wireguard_device device{};
  wireguard_peer* peer = nullptr;
  bool established = false;

  Impl(NodeKeyPair local_identity, Key32 peer_public,
       std::optional<Key32> preshared_key)
      : local(std::move(local_identity)), remote(peer_public), psk(std::move(preshared_key)) {
    initialize_wireguard_once();
    if (!wireguard_device_init(&device, local.private_key.data())) {
      throw std::runtime_error("failed to initialize native WireGuard device");
    }
    if (!std::equal(std::begin(device.public_key), std::end(device.public_key),
                    local.public_key.begin())) {
      throw std::runtime_error("native WireGuard public key does not match Tailcat node key");
    }
    peer = peer_alloc(&device);
    if (peer == nullptr) throw std::runtime_error("native WireGuard peer table is full");
    const std::uint8_t* psk_ptr = psk ? psk->data() : nullptr;
    if (!wireguard_peer_init(&device, peer, remote.data(), psk_ptr)) {
      throw std::runtime_error("failed to initialize native WireGuard peer");
    }
  }

  std::vector<std::uint8_t> initiate() {
    message_handshake_initiation message{};
    if (!wireguard_create_handshake_initiation(&device, peer, &message)) {
      throw std::runtime_error("failed to create WireGuard handshake initiation");
    }
    return bytes_of(&message, sizeof(message));
  }

  WireGuardPacketResult handle(std::span<const std::uint8_t> packet) {
    WireGuardPacketResult result;
    if (packet.empty()) return result;
    const auto type = wireguard_get_message_type(packet.data(), packet.size());

    switch (type) {
      case MESSAGE_HANDSHAKE_INITIATION: {
        if (packet.size() != sizeof(message_handshake_initiation)) return result;
        message_handshake_initiation message{};
        std::memcpy(&message, packet.data(), sizeof(message));
        if (!wireguard_check_mac1(
                &device, reinterpret_cast<const std::uint8_t*>(&message),
                sizeof(message) - 2U * WIREGUARD_COOKIE_LEN, message.mac1)) {
          return result;
        }
        auto* matched = wireguard_process_initiation_message(&device, &message);
        if (matched != peer) return result;

        message_handshake_response response{};
        if (!wireguard_create_handshake_response(&device, peer, &response)) {
          return result;
        }
        wireguard_start_session(peer, false);
        established = true;
        result.outbound = bytes_of(&response, sizeof(response));
        result.session_established = true;
        return result;
      }

      case MESSAGE_HANDSHAKE_RESPONSE: {
        if (packet.size() != sizeof(message_handshake_response)) return result;
        message_handshake_response message{};
        std::memcpy(&message, packet.data(), sizeof(message));
        if (!wireguard_check_mac1(
                &device, reinterpret_cast<const std::uint8_t*>(&message),
                sizeof(message) - 2U * WIREGUARD_COOKIE_LEN, message.mac1)) {
          return result;
        }
        auto* matched = peer_lookup_by_handshake(&device, message.receiver);
        if (matched != peer) return result;
        if (!wireguard_process_handshake_response(&device, peer, &message)) {
          return result;
        }
        wireguard_start_session(peer, true);
        established = true;
        result.session_established = true;
        return result;
      }

      case MESSAGE_COOKIE_REPLY: {
        if (packet.size() != sizeof(message_cookie_reply)) return result;
        message_cookie_reply message{};
        std::memcpy(&message, packet.data(), sizeof(message));
        auto* matched = peer_lookup_by_handshake(&device, message.receiver);
        if (matched == peer) {
          (void)wireguard_process_cookie_message(&device, peer, &message);
        }
        return result;
      }

      case MESSAGE_TRANSPORT_DATA: {
        if (packet.size() < sizeof(message_transport_data) + WIREGUARD_AUTHTAG_LEN) return result;
        const auto receiver = load_u32_le(packet.data() + 4U);
        auto* matched = peer_lookup_by_receiver(&device, receiver);
        if (matched != peer) return result;
        auto* keypair = get_peer_keypair_for_idx(peer, receiver);
        if (keypair == nullptr || !keypair->receiving_valid ||
            wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME)) {
          return result;
        }

        const auto encrypted_len = packet.size() - sizeof(message_transport_data);
        if (encrypted_len < WIREGUARD_AUTHTAG_LEN) return result;
        const auto plaintext_len = encrypted_len - WIREGUARD_AUTHTAG_LEN;
        std::vector<std::uint8_t> plaintext(plaintext_len);
        const auto counter = load_u64_le(packet.data() + 8U);
        if (!wireguard_decrypt_packet(plaintext.data(), packet.data() + sizeof(message_transport_data),
                                      encrypted_len, counter, keypair)) {
          return result;
        }
        if (!wireguard_check_replay(keypair, counter)) return result;

        const auto now = wireguard_sys_now();
        keypair->last_rx = now;
        peer->last_rx = now;
        keypair_update(peer, keypair);
        established = true;
        result.session_established = true;

        const auto length = inner_ip_length(plaintext);
        if (!length) return result;
        plaintext.resize(*length);
        result.plaintext_ip = std::move(plaintext);
        return result;
      }

      default:
        return result;
    }
  }

  std::vector<std::uint8_t> encrypt(std::span<const std::uint8_t> packet) {
    wireguard_keypair* keypair = &peer->curr_keypair;
    if (keypair->valid && !keypair->initiator && keypair->last_rx == 0U) {
      keypair = &peer->prev_keypair;
    }
    if (!keypair->valid ||
        wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) ||
        keypair->sending_counter >= REJECT_AFTER_MESSAGES) {
      throw std::runtime_error("WireGuard session is not ready for transport data");
    }
    if (packet.size() > std::numeric_limits<std::size_t>::max() - 15U) {
      throw std::length_error("WireGuard plaintext is too large");
    }
    const auto padded_len = (packet.size() + 15U) & ~std::size_t{15U};
    if (padded_len > std::numeric_limits<std::size_t>::max() - 32U) {
      throw std::length_error("WireGuard packet is too large");
    }

    std::vector<std::uint8_t> padded(padded_len, 0U);
    std::copy(packet.begin(), packet.end(), padded.begin());
    std::vector<std::uint8_t> out(sizeof(message_transport_data) + padded_len + WIREGUARD_AUTHTAG_LEN, 0U);
    out[0] = MESSAGE_TRANSPORT_DATA;
    store_u32_le(out.data() + 4U, keypair->remote_index);
    const auto counter = keypair->sending_counter;
    store_u64_le(out.data() + 8U, counter);
    wireguard_encrypt_packet(out.data() + sizeof(message_transport_data), padded.data(), padded.size(), keypair);

    const auto now = wireguard_sys_now();
    peer->last_tx = now;
    keypair->last_tx = now;
    if (keypair->sending_counter >= REKEY_AFTER_MESSAGES ||
        (keypair->initiator && wireguard_expired(keypair->keypair_millis, REKEY_AFTER_TIME))) {
      peer->send_handshake = true;
    }
    return out;
  }
};

WireGuardPeerEngine::WireGuardPeerEngine(NodeKeyPair local_identity,
                                         Key32 peer_public,
                                         std::optional<Key32> preshared_key)
    : impl_(std::make_unique<Impl>(std::move(local_identity), peer_public,
                                   std::move(preshared_key))) {}
WireGuardPeerEngine::~WireGuardPeerEngine() = default;
WireGuardPeerEngine::WireGuardPeerEngine(WireGuardPeerEngine&&) noexcept = default;
WireGuardPeerEngine& WireGuardPeerEngine::operator=(WireGuardPeerEngine&&) noexcept = default;

std::vector<std::uint8_t> WireGuardPeerEngine::create_handshake_initiation() {
  return impl_->initiate();
}
WireGuardPacketResult WireGuardPeerEngine::handle_packet(
    std::span<const std::uint8_t> packet) {
  return impl_->handle(packet);
}
std::vector<std::uint8_t> WireGuardPeerEngine::encrypt_ip_packet(
    std::span<const std::uint8_t> packet) {
  return impl_->encrypt(packet);
}
bool WireGuardPeerEngine::session_established() const noexcept {
  return impl_->established;
}
const Key32& WireGuardPeerEngine::peer_public_key() const noexcept {
  return impl_->remote;
}

}  // namespace tailcat
