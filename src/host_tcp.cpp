// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/host_tcp.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tailcat {
namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
using SocketLength = int;

int last_socket_error() noexcept { return WSAGetLastError(); }
bool interrupted(int error) noexcept { return error == WSAEINTR; }
void close_socket(NativeSocket socket) noexcept {
  if (socket != kInvalidSocket) (void)closesocket(socket);
}
std::string socket_error(std::string_view operation, int error) {
  return std::string(operation) + " failed (Winsock error " + std::to_string(error) + ")";
}
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
using SocketLength = socklen_t;

int last_socket_error() noexcept { return errno; }
bool interrupted(int error) noexcept { return error == EINTR; }
void close_socket(NativeSocket socket) noexcept {
  if (socket != kInvalidSocket) (void)::close(socket);
}
std::string socket_error(std::string_view operation, int error) {
  return std::string(operation) + " failed: " + std::strerror(error);
}
#endif

bool connect_native(NativeSocket socket, const sockaddr* address,
                    SocketLength length) {
#ifdef _WIN32
  return ::connect(socket, address, length) != SOCKET_ERROR;
#else
  return ::connect(socket, address, length) == 0;
#endif
}

NativeSocket connect_socket(const std::string& host, std::uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* addresses = nullptr;
  const auto service = std::to_string(port);
  const int gai = getaddrinfo(host.c_str(), service.c_str(), &hints, &addresses);
  if (gai != 0) {
#ifdef _WIN32
    throw std::runtime_error("getaddrinfo failed: " + std::to_string(gai));
#else
    throw std::runtime_error(std::string("getaddrinfo failed: ") + gai_strerror(gai));
#endif
  }

  NativeSocket result = kInvalidSocket;
  int last_error = 0;
  for (auto* address = addresses; address != nullptr; address = address->ai_next) {
    const auto socket = ::socket(address->ai_family, address->ai_socktype,
                                 address->ai_protocol);
    if (socket == kInvalidSocket) {
      last_error = last_socket_error();
      continue;
    }
    if (connect_native(socket, address->ai_addr,
                       static_cast<SocketLength>(address->ai_addrlen))) {
      result = socket;
      break;
    }
    last_error = last_socket_error();
    close_socket(socket);
  }
  freeaddrinfo(addresses);
  if (result == kInvalidSocket) {
    throw std::runtime_error(socket_error("connect", last_error));
  }
  return result;
}

std::uint16_t socket_port(NativeSocket socket) noexcept {
  sockaddr_storage address{};
  SocketLength length = static_cast<SocketLength>(sizeof(address));
  if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) != 0) return 0U;
  if (address.ss_family == AF_INET) {
    const auto* in = reinterpret_cast<const sockaddr_in*>(&address);
    return ntohs(in->sin_port);
  }
  if (address.ss_family == AF_INET6) {
    const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&address);
    return ntohs(in6->sin6_port);
  }
  return 0U;
}

NativeSocket listen_socket(const std::string& host, std::uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* addresses = nullptr;
  const auto service = std::to_string(port);
  const char* host_ptr = host.empty() ? nullptr : host.c_str();
  const int gai = getaddrinfo(host_ptr, service.c_str(), &hints, &addresses);
  if (gai != 0) {
#ifdef _WIN32
    throw std::runtime_error("getaddrinfo failed: " + std::to_string(gai));
#else
    throw std::runtime_error(std::string("getaddrinfo failed: ") + gai_strerror(gai));
#endif
  }

  NativeSocket result = kInvalidSocket;
  int last_error = 0;
  for (auto* address = addresses; address != nullptr; address = address->ai_next) {
    const auto socket = ::socket(address->ai_family, address->ai_socktype,
                                 address->ai_protocol);
    if (socket == kInvalidSocket) {
      last_error = last_socket_error();
      continue;
    }
    int one = 1;
#ifdef _WIN32
    (void)setsockopt(socket, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&one), sizeof(one));
#else
    (void)setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
    const auto len = static_cast<SocketLength>(address->ai_addrlen);
    if (::bind(socket, address->ai_addr, len) == 0 && ::listen(socket, 64) == 0) {
      result = socket;
      break;
    }
    last_error = last_socket_error();
    close_socket(socket);
  }
  freeaddrinfo(addresses);
  if (result == kInvalidSocket) {
    throw std::runtime_error(socket_error("listen", last_error));
  }
  return result;
}

}  // namespace

struct HostTcpStream::Impl {
  explicit Impl(NativeSocket native) : socket(native) {}
  ~Impl() { close_socket(socket); }
  NativeSocket socket = kInvalidSocket;
};

HostTcpStream::HostTcpStream(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
HostTcpStream::~HostTcpStream() = default;
HostTcpStream::HostTcpStream(HostTcpStream&&) noexcept = default;
HostTcpStream& HostTcpStream::operator=(HostTcpStream&&) noexcept = default;

std::shared_ptr<HostTcpStream> HostTcpStream::connect(const std::string& host,
                                                      std::uint16_t port) {
  return std::shared_ptr<HostTcpStream>(
      new HostTcpStream(std::make_unique<Impl>(connect_socket(host, port))));
}

std::vector<std::uint8_t> HostTcpStream::read_some(std::size_t max_bytes) {
  if (!open()) throw std::runtime_error("read from closed host TCP socket");
  if (max_bytes == 0U) return {};
  max_bytes = std::min(max_bytes, static_cast<std::size_t>(INT_MAX));
  std::vector<std::uint8_t> buffer(max_bytes);
  for (;;) {
#ifdef _WIN32
    const int received = ::recv(impl_->socket,
                                reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()), 0);
    if (received == SOCKET_ERROR) {
#else
    const auto received = ::recv(impl_->socket, buffer.data(), buffer.size(), 0);
    if (received < 0) {
#endif
      const int error = last_socket_error();
      if (interrupted(error)) continue;
      throw std::runtime_error(socket_error("recv", error));
    }
    if (received == 0) return {};
    buffer.resize(static_cast<std::size_t>(received));
    return buffer;
  }
}

void HostTcpStream::write_all(std::span<const std::uint8_t> data) {
  if (!open()) throw std::runtime_error("write to closed host TCP socket");
  std::size_t offset = 0U;
  while (offset < data.size()) {
    const auto amount = std::min(data.size() - offset,
                                 static_cast<std::size_t>(INT_MAX));
#ifdef _WIN32
    const int sent = ::send(impl_->socket,
                            reinterpret_cast<const char*>(data.data() + offset),
                            static_cast<int>(amount), 0);
    if (sent == SOCKET_ERROR) {
#else
    const auto sent = ::send(impl_->socket, data.data() + offset, amount, 0);
    if (sent < 0) {
#endif
      const int error = last_socket_error();
      if (interrupted(error)) continue;
      throw std::runtime_error(socket_error("send", error));
    }
    if (sent == 0) throw std::runtime_error("send returned zero bytes");
    offset += static_cast<std::size_t>(sent);
  }
}

void HostTcpStream::shutdown_write() {
  if (!open()) return;
#ifdef _WIN32
  if (::shutdown(impl_->socket, SD_SEND) == SOCKET_ERROR) {
#else
  if (::shutdown(impl_->socket, SHUT_WR) != 0) {
#endif
    const int error = last_socket_error();
    throw std::runtime_error(socket_error("shutdown", error));
  }
}

void HostTcpStream::close() noexcept {
  if (!impl_ || impl_->socket == kInvalidSocket) return;
  close_socket(impl_->socket);
  impl_->socket = kInvalidSocket;
}

bool HostTcpStream::open() const noexcept {
  return impl_ && impl_->socket != kInvalidSocket;
}

struct HostTcpListener::Impl {
  explicit Impl(NativeSocket native) : socket(native), bound_port(socket_port(native)) {}
  ~Impl() { close_socket(socket); }
  NativeSocket socket = kInvalidSocket;
  std::uint16_t bound_port = 0U;
};

HostTcpListener::HostTcpListener(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
HostTcpListener::~HostTcpListener() = default;
HostTcpListener::HostTcpListener(HostTcpListener&&) noexcept = default;
HostTcpListener& HostTcpListener::operator=(HostTcpListener&&) noexcept = default;

HostTcpListener HostTcpListener::listen(const std::string& host, std::uint16_t port) {
  return HostTcpListener(std::make_unique<Impl>(listen_socket(host, port)));
}

std::shared_ptr<HostTcpStream> HostTcpListener::accept() {
  if (!impl_ || impl_->socket == kInvalidSocket) {
    throw std::runtime_error("accept on closed host TCP listener");
  }
  for (;;) {
    const auto socket = ::accept(impl_->socket, nullptr, nullptr);
    if (socket != kInvalidSocket) {
      return std::shared_ptr<HostTcpStream>(
          new HostTcpStream(std::make_unique<HostTcpStream::Impl>(socket)));
    }
    const int error = last_socket_error();
    if (interrupted(error)) continue;
    throw std::runtime_error(socket_error("accept", error));
  }
}

std::uint16_t HostTcpListener::port() const noexcept {
  return impl_ ? impl_->bound_port : 0U;
}

void HostTcpListener::close() noexcept {
  if (!impl_ || impl_->socket == kInvalidSocket) return;
  close_socket(impl_->socket);
  impl_->socket = kInvalidSocket;
}

}  // namespace tailcat
