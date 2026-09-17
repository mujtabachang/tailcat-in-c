// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/lwip_udp.hpp"

extern "C" {
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"
}

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace tailcat {
namespace {

ip_addr_t to_lwip_ip(const Ip6Address& bytes) {
  ip_addr_t out{};
  IP_SET_TYPE_VAL(out, IPADDR_TYPE_V6);
  auto* ip6 = ip_2_ip6(&out);
  IP6_ADDR_PART(ip6, 0, bytes[0], bytes[1], bytes[2], bytes[3]);
  IP6_ADDR_PART(ip6, 1, bytes[4], bytes[5], bytes[6], bytes[7]);
  IP6_ADDR_PART(ip6, 2, bytes[8], bytes[9], bytes[10], bytes[11]);
  IP6_ADDR_PART(ip6, 3, bytes[12], bytes[13], bytes[14], bytes[15]);
  ip6_addr_clear_zone(ip6);
  return out;
}

Ip6Address from_lwip_ip(const ip_addr_t* address) {
  Ip6Address out{};
  if (address == nullptr || !IP_IS_V6(address)) return out;
  const auto* ip6 = ip_2_ip6(address);
  for (std::size_t i = 0; i < 4U; ++i) {
    const auto word = lwip_htonl(ip6->addr[i]);
    out[i * 4U] = static_cast<std::uint8_t>((word >> 24U) & 0xffU);
    out[i * 4U + 1U] = static_cast<std::uint8_t>((word >> 16U) & 0xffU);
    out[i * 4U + 2U] = static_cast<std::uint8_t>((word >> 8U) & 0xffU);
    out[i * 4U + 3U] = static_cast<std::uint8_t>(word & 0xffU);
  }
  return out;
}

std::string lwip_error(err_t err) {
  return std::string("lwIP error ") + std::to_string(static_cast<int>(err));
}

}  // namespace

struct LwipUdpSocket::Impl {
  udp_pcb* pcb = nullptr;
  bool is_connected = false;
  std::deque<LwipUdpDatagram> received;

  ~Impl() { close(); }

  void close() noexcept {
    if (pcb == nullptr) return;
    udp_recv(pcb, nullptr, nullptr);
    udp_remove(pcb);
    pcb = nullptr;
    is_connected = false;
  }
};

namespace {

void udp_received(void* arg, udp_pcb*, pbuf* p, const ip_addr_t* address,
                  u16_t port) {
  auto* socket = static_cast<LwipUdpSocket::Impl*>(arg);
  if (p == nullptr) return;
  if (socket == nullptr || address == nullptr || !IP_IS_V6(address)) {
    pbuf_free(p);
    return;
  }

  try {
    LwipUdpDatagram datagram;
    datagram.remote_address = from_lwip_ip(address);
    datagram.remote_port = port;
    datagram.payload.resize(static_cast<std::size_t>(p->tot_len));
    if (pbuf_copy_partial(p, datagram.payload.data(), p->tot_len, 0) != p->tot_len) {
      pbuf_free(p);
      return;
    }
    socket->received.push_back(std::move(datagram));
  } catch (...) {
    // lwIP callbacks cannot propagate C++ exceptions through C frames.
  }
  pbuf_free(p);
}

std::shared_ptr<LwipUdpSocket::Impl> new_udp_socket() {
  auto impl = std::make_shared<LwipUdpSocket::Impl>();
  impl->pcb = udp_new_ip_type(IPADDR_TYPE_V6);
  if (impl->pcb == nullptr) throw std::runtime_error("udp_new_ip_type failed");
  udp_recv(impl->pcb, udp_received, impl.get());
  return impl;
}

pbuf* packet_buffer(std::span<const std::uint8_t> payload) {
  if (payload.size() > static_cast<std::size_t>(std::numeric_limits<u16_t>::max())) {
    throw std::length_error("UDP datagram exceeds lwIP pbuf size");
  }
  auto* p = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload.size()), PBUF_RAM);
  if (p == nullptr) throw std::runtime_error("pbuf_alloc failed for UDP datagram");
  if (!payload.empty() && pbuf_take(p, payload.data(), payload.size()) != ERR_OK) {
    pbuf_free(p);
    throw std::runtime_error("pbuf_take failed for UDP datagram");
  }
  return p;
}

}  // namespace

LwipUdpSocket::LwipUdpSocket(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}
LwipUdpSocket::~LwipUdpSocket() = default;

std::shared_ptr<LwipUdpSocket> LwipUdpSocket::bind(std::uint16_t port) {
  auto impl = new_udp_socket();
  if (const auto err = udp_bind(impl->pcb, IP_ANY_TYPE, port); err != ERR_OK) {
    impl->close();
    throw std::runtime_error("udp_bind: " + lwip_error(err));
  }
  return std::shared_ptr<LwipUdpSocket>(new LwipUdpSocket(std::move(impl)));
}

std::shared_ptr<LwipUdpSocket> LwipUdpSocket::connect(const Ip6Address& remote,
                                                      std::uint16_t port) {
  if (port == 0U) throw std::invalid_argument("UDP remote port must be non-zero");
  auto impl = new_udp_socket();
  const auto destination = to_lwip_ip(remote);
  if (const auto err = udp_connect(impl->pcb, &destination, port); err != ERR_OK) {
    impl->close();
    throw std::runtime_error("udp_connect: " + lwip_error(err));
  }
  impl->is_connected = true;
  return std::shared_ptr<LwipUdpSocket>(new LwipUdpSocket(std::move(impl)));
}

std::uint16_t LwipUdpSocket::local_port() const noexcept {
  return impl_ && impl_->pcb ? impl_->pcb->local_port : 0U;
}

bool LwipUdpSocket::connected() const noexcept {
  return impl_ && impl_->pcb && impl_->is_connected;
}

bool LwipUdpSocket::open() const noexcept { return impl_ && impl_->pcb != nullptr; }

void LwipUdpSocket::send(std::span<const std::uint8_t> payload) {
  if (!open()) throw std::runtime_error("send on closed lwIP UDP socket");
  if (!connected()) throw std::runtime_error("send requires a connected lwIP UDP socket");
  auto* p = packet_buffer(payload);
  const auto err = udp_send(impl_->pcb, p);
  pbuf_free(p);
  if (err != ERR_OK) throw std::runtime_error("udp_send: " + lwip_error(err));
}

void LwipUdpSocket::send_to(const Ip6Address& remote, std::uint16_t port,
                            std::span<const std::uint8_t> payload) {
  if (!open()) throw std::runtime_error("send_to on closed lwIP UDP socket");
  if (port == 0U) throw std::invalid_argument("UDP remote port must be non-zero");
  const auto destination = to_lwip_ip(remote);
  auto* p = packet_buffer(payload);
  const auto err = udp_sendto(impl_->pcb, p, &destination, port);
  pbuf_free(p);
  if (err != ERR_OK) throw std::runtime_error("udp_sendto: " + lwip_error(err));
}

std::optional<LwipUdpDatagram> LwipUdpSocket::receive() {
  if (!impl_ || impl_->received.empty()) return std::nullopt;
  auto datagram = std::move(impl_->received.front());
  impl_->received.pop_front();
  return datagram;
}

void LwipUdpSocket::close() noexcept {
  if (impl_) impl_->close();
}

}  // namespace tailcat
