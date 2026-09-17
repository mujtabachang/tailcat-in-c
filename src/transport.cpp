// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/transport.hpp"

#include <array>
#include <charconv>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tailcat {
namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
using SocketLength = int;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
using SocketLength = socklen_t;
constexpr NativeSocket kInvalidSocket = -1;
#endif

class Socket {
 public:
  Socket() = default;
  explicit Socket(NativeSocket value) : value_(value) {}
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept : value_(other.release()) {}
  Socket& operator=(Socket&& other) noexcept {
    if (this != &other) {
      reset(other.release());
    }
    return *this;
  }
  ~Socket() { reset(); }

  [[nodiscard]] NativeSocket get() const noexcept { return value_; }
  [[nodiscard]] bool valid() const noexcept { return value_ != kInvalidSocket; }

  NativeSocket release() noexcept {
    const NativeSocket value = value_;
    value_ = kInvalidSocket;
    return value;
  }

  void reset(NativeSocket value = kInvalidSocket) noexcept {
    if (valid()) {
#ifdef _WIN32
      closesocket(value_);
#else
      close(value_);
#endif
    }
    value_ = value;
  }

 private:
  NativeSocket value_ = kInvalidSocket;
};

std::string socket_error_text(std::string_view operation) {
#ifdef _WIN32
  return std::string(operation) + " failed with Winsock error " + std::to_string(WSAGetLastError());
#else
  return std::string(operation) + " failed: " + std::strerror(errno);
#endif
}

std::string gai_error_text(int code) {
#ifdef _WIN32
  return "Winsock address resolution error " + std::to_string(code);
#else
  const char* text = gai_strerror(code);
  return text != nullptr ? text : "unknown address resolution error";
#endif
}

bool interrupted_socket_error() {
#ifdef _WIN32
  return WSAGetLastError() == WSAEINTR;
#else
  return errno == EINTR;
#endif
}

void configure_socket(Socket& socket) {
#ifdef __APPLE__
  int enabled = 1;
  (void)setsockopt(socket.get(), SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#else
  (void)socket;
#endif
}

int send_flags() {
#ifdef MSG_NOSIGNAL
  return MSG_NOSIGNAL;
#else
  return 0;
#endif
}

bool send_all(NativeSocket socket, const char* data, std::size_t size) {
  std::size_t sent = 0;
  while (sent < size) {
#ifdef _WIN32
    const int chunk = static_cast<int>(size - sent);
    const int n = send(socket, data + sent, chunk, send_flags());
#else
    const auto n = send(socket, data + sent, size - sent, send_flags());
#endif
    if (n > 0) {
      sent += static_cast<std::size_t>(n);
      continue;
    }
    if (n < 0 && interrupted_socket_error()) {
      continue;
    }
    return false;
  }
  return true;
}

void shutdown_write(NativeSocket socket) noexcept {
#ifdef _WIN32
  (void)shutdown(socket, SD_SEND);
#else
  (void)shutdown(socket, SHUT_WR);
#endif
}

int relay_stdio(Socket socket) {
  const NativeSocket raw_socket = socket.get();

  std::thread sender([raw_socket] {
    std::array<char, 16 * 1024> buffer{};
    while (std::cin.good()) {
      std::cin.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
      const std::streamsize count = std::cin.gcount();
      if (count <= 0) {
        break;
      }
      if (!send_all(raw_socket, buffer.data(), static_cast<std::size_t>(count))) {
        return;
      }
    }
    shutdown_write(raw_socket);
  });
  sender.detach();

  std::array<char, 16 * 1024> buffer{};
  for (;;) {
#ifdef _WIN32
    const int n = recv(raw_socket, buffer.data(), static_cast<int>(buffer.size()), 0);
#else
    const auto n = recv(raw_socket, buffer.data(), buffer.size(), 0);
#endif
    if (n > 0) {
      std::cout.write(buffer.data(), static_cast<std::streamsize>(n));
      std::cout.flush();
      continue;
    }
    if (n == 0) {
      return 0;
    }
    if (interrupted_socket_error()) {
      continue;
    }
    throw std::runtime_error(socket_error_text("recv"));
  }
}

std::uint16_t parse_port(std::string_view value, bool allow_zero) {
  unsigned int parsed = 0;
  const auto [ptr, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (error != std::errc{} || ptr != value.data() + value.size() || parsed > 65535U || (!allow_zero && parsed == 0U)) {
    throw std::invalid_argument("invalid TCP port: " + std::string(value));
  }
  return static_cast<std::uint16_t>(parsed);
}

std::string discover_local_ipv4() {
  std::array<char, 256> hostname{};
  if (gethostname(hostname.data(), static_cast<int>(hostname.size())) != 0) {
    return "127.0.0.1";
  }

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* results = nullptr;
  if (getaddrinfo(hostname.data(), nullptr, &hints, &results) != 0) {
    return "127.0.0.1";
  }

  std::string fallback = "127.0.0.1";
  for (addrinfo* result = results; result != nullptr; result = result->ai_next) {
    char host[NI_MAXHOST]{};
    if (getnameinfo(result->ai_addr, static_cast<SocketLength>(result->ai_addrlen), host, sizeof(host), nullptr, 0,
                    NI_NUMERICHOST) != 0) {
      continue;
    }
    fallback = host;
    if (fallback.rfind("127.", 0) != 0) {
      break;
    }
  }
  freeaddrinfo(results);
  return fallback;
}

Socket make_listener(std::string_view bind_host, std::uint16_t port, std::uint16_t& actual_port) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;

  const std::string host(bind_host);
  const std::string service = std::to_string(port);
  const char* node = (host.empty() || host == "*" || host == "0.0.0.0" || host == "::") ? nullptr : host.c_str();

  addrinfo* results = nullptr;
  const int resolve_error = getaddrinfo(node, service.c_str(), &hints, &results);
  if (resolve_error != 0) {
    throw std::runtime_error("unable to resolve bind address: " + gai_error_text(resolve_error));
  }

  Socket listener;
  for (addrinfo* result = results; result != nullptr; result = result->ai_next) {
    Socket candidate(::socket(result->ai_family, result->ai_socktype, result->ai_protocol));
    if (!candidate.valid()) {
      continue;
    }
    configure_socket(candidate);

    int reuse = 1;
#ifdef _WIN32
    (void)setsockopt(candidate.get(), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#else
    (void)setsockopt(candidate.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif

    if (bind(candidate.get(), result->ai_addr, static_cast<SocketLength>(result->ai_addrlen)) != 0) {
      continue;
    }
    if (listen(candidate.get(), 1) != 0) {
      continue;
    }
    listener = std::move(candidate);
    break;
  }
  freeaddrinfo(results);

  if (!listener.valid()) {
    throw std::runtime_error(socket_error_text("bind/listen"));
  }

  sockaddr_storage address{};
  SocketLength address_length = static_cast<SocketLength>(sizeof(address));
  if (getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address), &address_length) != 0) {
    throw std::runtime_error(socket_error_text("getsockname"));
  }
  char service_buffer[NI_MAXSERV]{};
  if (getnameinfo(reinterpret_cast<sockaddr*>(&address), address_length, nullptr, 0, service_buffer,
                  sizeof(service_buffer), NI_NUMERICSERV) != 0) {
    throw std::runtime_error("unable to determine listening port");
  }
  actual_port = parse_port(service_buffer, false);
  return listener;
}

Socket connect_to(const TcpEndpoint& endpoint) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  const std::string service = std::to_string(endpoint.port);
  addrinfo* results = nullptr;
  const int resolve_error = getaddrinfo(endpoint.host.c_str(), service.c_str(), &hints, &results);
  if (resolve_error != 0) {
    throw std::runtime_error("unable to resolve " + endpoint.host + ": " + gai_error_text(resolve_error));
  }

  Socket connected;
  for (addrinfo* result = results; result != nullptr; result = result->ai_next) {
    Socket candidate(::socket(result->ai_family, result->ai_socktype, result->ai_protocol));
    if (!candidate.valid()) {
      continue;
    }
    configure_socket(candidate);
    if (connect(candidate.get(), result->ai_addr, static_cast<SocketLength>(result->ai_addrlen)) == 0) {
      connected = std::move(candidate);
      break;
    }
  }
  freeaddrinfo(results);

  if (!connected.valid()) {
    throw std::runtime_error(socket_error_text("connect"));
  }
  return connected;
}

}  // namespace

TcpEndpoint parse_tcp_endpoint(std::string_view value) {
  constexpr std::string_view prefix = "tcp://";
  if (!value.starts_with(prefix)) {
    throw std::invalid_argument("TCP endpoint must start with tcp://");
  }

  const std::string_view address = value.substr(prefix.size());
  if (address.empty()) {
    throw std::invalid_argument("TCP endpoint is missing host and port");
  }

  std::string_view host;
  std::string_view port;
  if (address.front() == '[') {
    const std::size_t close = address.find(']');
    if (close == std::string_view::npos || close + 1 >= address.size() || address[close + 1] != ':') {
      throw std::invalid_argument("invalid bracketed IPv6 TCP endpoint");
    }
    host = address.substr(1, close - 1);
    port = address.substr(close + 2);
  } else {
    const std::size_t colon = address.rfind(':');
    if (colon == std::string_view::npos) {
      throw std::invalid_argument("TCP endpoint is missing port");
    }
    host = address.substr(0, colon);
    port = address.substr(colon + 1);
  }

  if (host.empty()) {
    throw std::invalid_argument("TCP endpoint is missing host");
  }
  return TcpEndpoint{std::string(host), parse_port(port, false)};
}

std::string format_tcp_endpoint(const TcpEndpoint& endpoint) {
  const bool ipv6 = endpoint.host.find(':') != std::string::npos;
  return std::string("tcp://") + (ipv6 ? "[" : "") + endpoint.host + (ipv6 ? "]" : "") + ":" +
         std::to_string(endpoint.port);
}

int run_tcp_listener(std::string_view bind_host, std::uint16_t port) {
  std::uint16_t actual_port = 0;
  Socket listener = make_listener(bind_host, port, actual_port);

  std::string advertised_host(bind_host);
  if (advertised_host.empty() || advertised_host == "*" || advertised_host == "0.0.0.0" || advertised_host == "::") {
    advertised_host = discover_local_ipv4();
  }

  const TcpEndpoint endpoint{advertised_host, actual_port};
  std::cout << "# 🐈 Native TCP listener: " << format_tcp_endpoint(endpoint) << '\n'
            << "# Direct TCP bootstrap mode; upstream tc... addresses are not supported yet.\n";
  std::cout.flush();

  sockaddr_storage peer{};
  SocketLength peer_length = static_cast<SocketLength>(sizeof(peer));
  Socket connection(accept(listener.get(), reinterpret_cast<sockaddr*>(&peer), &peer_length));
  if (!connection.valid()) {
    throw std::runtime_error(socket_error_text("accept"));
  }
  configure_socket(connection);
  listener.reset();
  return relay_stdio(std::move(connection));
}

int run_tcp_client(const TcpEndpoint& endpoint) {
  return relay_stdio(connect_to(endpoint));
}

}  // namespace tailcat
