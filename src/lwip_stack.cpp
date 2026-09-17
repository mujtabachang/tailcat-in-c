// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/lwip_stack.hpp"

extern "C" {
#include "lwip/init.h"
#include "lwip/ip6.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
}

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace tailcat {
namespace {

std::mutex g_stack_mutex;
bool g_stack_active = false;
std::once_flag g_lwip_once;

ip6_addr_t to_lwip(const Ip6Address& bytes) {
  ip6_addr_t out{};
  IP6_ADDR_PART(&out, 0, bytes[0], bytes[1], bytes[2], bytes[3]);
  IP6_ADDR_PART(&out, 1, bytes[4], bytes[5], bytes[6], bytes[7]);
  IP6_ADDR_PART(&out, 2, bytes[8], bytes[9], bytes[10], bytes[11]);
  IP6_ADDR_PART(&out, 3, bytes[12], bytes[13], bytes[14], bytes[15]);
  ip6_addr_clear_zone(&out);
  return out;
}

std::string lwip_error(err_t err) {
  return std::string("lwIP error ") + std::to_string(static_cast<int>(err));
}

}  // namespace

struct LwipTcpStream::Impl {
  tcp_pcb* pcb = nullptr;
  bool is_connected = false;
  bool is_eof = false;
  bool is_failed = false;
  bool write_closed = false;
  std::string error_message;
  std::deque<std::uint8_t> received;

  ~Impl() { abort(); }

  void abort() noexcept {
    if (pcb == nullptr) return;
    tcp_arg(pcb, nullptr);
    tcp_recv(pcb, nullptr);
    tcp_sent(pcb, nullptr);
    tcp_err(pcb, nullptr);
    tcp_poll(pcb, nullptr, 0);
    tcp_abort(pcb);
    pcb = nullptr;
  }
};

namespace {

void configure_stream(const std::shared_ptr<LwipTcpStream::Impl>& stream);

err_t stream_recv(void* arg, tcp_pcb* pcb, pbuf* p, err_t err) {
  auto* stream = static_cast<LwipTcpStream::Impl*>(arg);
  if (stream == nullptr) {
    if (p != nullptr) pbuf_free(p);
    return ERR_ABRT;
  }
  if (err != ERR_OK) return err;
  if (p == nullptr) {
    stream->is_eof = true;
    return ERR_OK;
  }

  const auto length = static_cast<std::size_t>(p->tot_len);
  std::vector<std::uint8_t> temp(length);
  const auto copied = pbuf_copy_partial(p, temp.data(), p->tot_len, 0);
  if (copied != p->tot_len) {
    pbuf_free(p);
    stream->is_failed = true;
    stream->error_message = "failed to copy lwIP TCP receive buffer";
    return ERR_BUF;
  }
  stream->received.insert(stream->received.end(), temp.begin(), temp.end());
  tcp_recved(pcb, p->tot_len);
  pbuf_free(p);
  return ERR_OK;
}

err_t stream_sent(void*, tcp_pcb*, u16_t) { return ERR_OK; }

void stream_error(void* arg, err_t err) {
  auto* stream = static_cast<LwipTcpStream::Impl*>(arg);
  if (stream == nullptr) return;
  stream->pcb = nullptr;  // lwIP already freed it before invoking tcp_err.
  stream->is_failed = true;
  stream->error_message = lwip_error(err);
}

err_t stream_poll(void*, tcp_pcb* pcb) { return tcp_output(pcb); }

err_t stream_connected(void* arg, tcp_pcb*, err_t err) {
  auto* stream = static_cast<LwipTcpStream::Impl*>(arg);
  if (stream == nullptr) return ERR_ARG;
  if (err != ERR_OK) {
    stream->is_failed = true;
    stream->error_message = lwip_error(err);
    return err;
  }
  stream->is_connected = true;
  return ERR_OK;
}

void configure_stream(const std::shared_ptr<LwipTcpStream::Impl>& stream) {
  tcp_arg(stream->pcb, stream.get());
  tcp_recv(stream->pcb, stream_recv);
  tcp_sent(stream->pcb, stream_sent);
  tcp_err(stream->pcb, stream_error);
  tcp_poll(stream->pcb, stream_poll, 2);
}

}  // namespace

struct LwipTcpListener::Impl {
  tcp_pcb* pcb = nullptr;
  std::uint16_t bound_port = 0;
  std::deque<std::shared_ptr<LwipTcpStream::Impl>> accepted;

  ~Impl() { close(); }

  void close() noexcept {
    if (pcb == nullptr) return;
    tcp_arg(pcb, nullptr);
    tcp_accept(pcb, nullptr);
    if (tcp_close(pcb) != ERR_OK) tcp_abort(pcb);
    pcb = nullptr;
  }
};

namespace {

err_t listener_accept(void* arg, tcp_pcb* new_pcb, err_t err) {
  auto* listener = static_cast<LwipTcpListener::Impl*>(arg);
  if (listener == nullptr || new_pcb == nullptr) {
    if (new_pcb != nullptr) tcp_abort(new_pcb);
    return ERR_ABRT;
  }
  if (err != ERR_OK) return err;

  auto stream = std::make_shared<LwipTcpStream::Impl>();
  stream->pcb = new_pcb;
  stream->is_connected = true;
  configure_stream(stream);
  listener->accepted.push_back(std::move(stream));
  return ERR_OK;
}

}  // namespace

struct LwipStack::Impl {
  Ip6Address local{};
  SendIp send_ip;
  netif interface{};
  bool added = false;

  Impl(Ip6Address address, SendIp sender)
      : local(address), send_ip(std::move(sender)) {}

  static err_t initialize_netif(netif* n) {
    if (n == nullptr || n->state == nullptr) return ERR_ARG;
    n->name[0] = 't';
    n->name[1] = 'c';
    n->mtu = 1280U;
    n->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    n->output_ip6 = output_ipv6;
    return ERR_OK;
  }

  static err_t output_ipv6(netif* n, pbuf* p, const ip6_addr_t*) {
    if (n == nullptr || n->state == nullptr || p == nullptr) return ERR_ARG;
    auto* self = static_cast<Impl*>(n->state);
    try {
      std::vector<std::uint8_t> packet(static_cast<std::size_t>(p->tot_len));
      const auto copied = pbuf_copy_partial(p, packet.data(), p->tot_len, 0);
      if (copied != p->tot_len) return ERR_BUF;
      self->send_ip(std::move(packet));
      return ERR_OK;
    } catch (...) {
      return ERR_IF;
    }
  }
};

LwipTcpStream::LwipTcpStream(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}
LwipTcpStream::~LwipTcpStream() = default;
bool LwipTcpStream::connected() const noexcept { return impl_->is_connected; }
bool LwipTcpStream::eof() const noexcept { return impl_->is_eof; }
bool LwipTcpStream::failed() const noexcept { return impl_->is_failed; }
const std::string& LwipTcpStream::error() const noexcept { return impl_->error_message; }
std::size_t LwipTcpStream::buffered() const noexcept { return impl_->received.size(); }

std::size_t LwipTcpStream::write(std::span<const std::uint8_t> data) {
  if (impl_->pcb == nullptr || !impl_->is_connected || impl_->write_closed) return 0U;
  const auto available = static_cast<std::size_t>(tcp_sndbuf(impl_->pcb));
  const auto amount = std::min({data.size(), available,
                                static_cast<std::size_t>(std::numeric_limits<u16_t>::max())});
  if (amount == 0U) return 0U;
  const auto err = tcp_write(impl_->pcb, data.data(), static_cast<u16_t>(amount), TCP_WRITE_FLAG_COPY);
  if (err == ERR_MEM) return 0U;
  if (err != ERR_OK) throw std::runtime_error("tcp_write: " + lwip_error(err));
  const auto output_err = tcp_output(impl_->pcb);
  if (output_err != ERR_OK && output_err != ERR_MEM) {
    throw std::runtime_error("tcp_output: " + lwip_error(output_err));
  }
  return amount;
}

std::vector<std::uint8_t> LwipTcpStream::read_available(std::size_t max_bytes) {
  const auto count = std::min(max_bytes, impl_->received.size());
  std::vector<std::uint8_t> out;
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(impl_->received.front());
    impl_->received.pop_front();
  }
  return out;
}

void LwipTcpStream::shutdown_write() {
  if (impl_->pcb == nullptr || impl_->write_closed) return;
  const auto err = tcp_shutdown(impl_->pcb, 0, 1);
  if (err != ERR_OK) throw std::runtime_error("tcp_shutdown: " + lwip_error(err));
  impl_->write_closed = true;
}

void LwipTcpStream::close() {
  if (impl_->pcb == nullptr) return;
  auto* pcb = impl_->pcb;
  tcp_arg(pcb, nullptr);
  tcp_recv(pcb, nullptr);
  tcp_sent(pcb, nullptr);
  tcp_err(pcb, nullptr);
  tcp_poll(pcb, nullptr, 0);
  const auto err = tcp_close(pcb);
  if (err != ERR_OK) {
    tcp_abort(pcb);
  }
  impl_->pcb = nullptr;
}

LwipTcpListener::LwipTcpListener(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}
LwipTcpListener::~LwipTcpListener() = default;
std::uint16_t LwipTcpListener::port() const noexcept { return impl_->bound_port; }
std::shared_ptr<LwipTcpStream> LwipTcpListener::accept() {
  if (impl_->accepted.empty()) return {};
  auto stream = std::move(impl_->accepted.front());
  impl_->accepted.pop_front();
  return std::shared_ptr<LwipTcpStream>(new LwipTcpStream(std::move(stream)));
}
void LwipTcpListener::close() { impl_->close(); }

LwipStack::LwipStack(Ip6Address local_address, SendIp send_ip)
    : impl_(std::make_unique<Impl>(local_address, std::move(send_ip))) {
  if (!impl_->send_ip) throw std::invalid_argument("lwIP send callback is required");
  {
    std::lock_guard<std::mutex> lock(g_stack_mutex);
    if (g_stack_active) throw std::runtime_error("only one Tailcat lwIP stack may exist per process");
    g_stack_active = true;
  }
  try {
    std::call_once(g_lwip_once, [] { lwip_init(); });
    if (netif_add_noaddr(&impl_->interface, impl_.get(), Impl::initialize_netif, ip6_input) == nullptr) {
      throw std::runtime_error("netif_add_noaddr failed");
    }
    impl_->added = true;
    const auto local = to_lwip(impl_->local);
    netif_ip6_addr_set(&impl_->interface, 0, &local);
    netif_ip6_addr_set_state(&impl_->interface, 0, IP6_ADDR_PREFERRED);
    netif_set_default(&impl_->interface);
    netif_set_link_up(&impl_->interface);
    netif_set_up(&impl_->interface);
  } catch (...) {
    std::lock_guard<std::mutex> lock(g_stack_mutex);
    g_stack_active = false;
    throw;
  }
}

LwipStack::~LwipStack() {
  if (impl_->added) {
    netif_set_down(&impl_->interface);
    netif_remove(&impl_->interface);
  }
  std::lock_guard<std::mutex> lock(g_stack_mutex);
  g_stack_active = false;
}

const Ip6Address& LwipStack::local_address() const noexcept { return impl_->local; }

std::shared_ptr<LwipTcpListener> LwipStack::listen(std::uint16_t port) {
  auto listener = std::make_shared<LwipTcpListener::Impl>();
  auto* pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
  if (pcb == nullptr) throw std::runtime_error("tcp_new_ip_type failed");
  if (const auto err = tcp_bind(pcb, IP_ANY_TYPE, port); err != ERR_OK) {
    tcp_abort(pcb);
    throw std::runtime_error("tcp_bind: " + lwip_error(err));
  }
  auto* listening = tcp_listen(pcb);
  if (listening == nullptr) {
    tcp_abort(pcb);
    throw std::runtime_error("tcp_listen failed");
  }
  listener->pcb = listening;
  listener->bound_port = listening->local_port;
  tcp_arg(listening, listener.get());
  tcp_accept(listening, listener_accept);
  return std::shared_ptr<LwipTcpListener>(new LwipTcpListener(std::move(listener)));
}

std::shared_ptr<LwipTcpStream> LwipStack::connect(const Ip6Address& remote,
                                                  std::uint16_t port) {
  auto stream = std::make_shared<LwipTcpStream::Impl>();
  stream->pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
  if (stream->pcb == nullptr) throw std::runtime_error("tcp_new_ip_type failed");
  configure_stream(stream);

  ip_addr_t destination{};
  IP_SET_TYPE_VAL(destination, IPADDR_TYPE_V6);
  const auto remote6 = to_lwip(remote);
  ip6_addr_copy(*ip_2_ip6(&destination), remote6);
  const auto err = tcp_connect(stream->pcb, &destination, port, stream_connected);
  if (err != ERR_OK) {
    stream->abort();
    throw std::runtime_error("tcp_connect: " + lwip_error(err));
  }
  return std::shared_ptr<LwipTcpStream>(new LwipTcpStream(std::move(stream)));
}

void LwipStack::input_ip(std::span<const std::uint8_t> packet) {
  if (packet.empty() || (packet[0] >> 4U) != 6U) return;
  if (packet.size() > static_cast<std::size_t>(std::numeric_limits<u16_t>::max())) {
    throw std::length_error("IPv6 packet exceeds lwIP pbuf size");
  }
  auto* p = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(packet.size()), PBUF_RAM);
  if (p == nullptr) throw std::runtime_error("pbuf_alloc failed");
  if (pbuf_take(p, packet.data(), packet.size()) != ERR_OK) {
    pbuf_free(p);
    throw std::runtime_error("pbuf_take failed");
  }
  // ip6_input consumes p regardless of whether the packet is accepted.
  (void)ip6_input(p, &impl_->interface);
}

void LwipStack::poll() { sys_check_timeouts(); }

}  // namespace tailcat
