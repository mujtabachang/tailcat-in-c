// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/derp_http.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace tailcat {
namespace {

using Clock = std::chrono::steady_clock;

void curl_global_once() {
  static std::once_flag once;
  std::call_once(once, [] {
    const auto rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK) throw std::runtime_error("curl_global_init failed");
  });
}

std::string curl_error(CURLcode code) { return std::string(curl_easy_strerror(code)); }

}  // namespace

struct DerpHttpClient::Impl {
  DerpNode node;
  NodeKeyPair identity;
  std::string app_name;
  CURL* curl = nullptr;
  Key32 server_public{};
  bool is_connected = false;
  std::vector<std::uint8_t> receive_buffer;

  Impl(DerpNode n, NodeKeyPair i, std::string app)
      : node(std::move(n)), identity(std::move(i)), app_name(std::move(app)) {}

  ~Impl() { close(); }

  std::uint16_t port() const {
    if (node.derp_port <= 0) return node.insecure_for_tests ? 80U : 443U;
    if (node.derp_port > 65535) throw std::runtime_error("invalid DERP port");
    return static_cast<std::uint16_t>(node.derp_port);
  }

  std::string host() const {
    if (node.host_name.empty()) throw std::runtime_error("DERP node has no hostname");
    return node.host_name;
  }

  std::string authority() const {
    const auto h = host();
    const auto p = port();
    const auto default_port = node.insecure_for_tests ? 80U : 443U;
    return p == default_port ? h : h + ":" + std::to_string(p);
  }

  void close() noexcept {
    is_connected = false;
    receive_buffer.clear();
    if (curl != nullptr) {
      curl_easy_cleanup(curl);
      curl = nullptr;
    }
  }

  void setopt(CURLoption option, long value) {
    const auto rc = curl_easy_setopt(curl, option, value);
    if (rc != CURLE_OK) throw std::runtime_error("curl option failed: " + curl_error(rc));
  }

  void setopt(CURLoption option, const char* value) {
    const auto rc = curl_easy_setopt(curl, option, value);
    if (rc != CURLE_OK) throw std::runtime_error("curl option failed: " + curl_error(rc));
  }

  void send_all(const std::uint8_t* data, std::size_t size) {
    std::size_t sent = 0;
    while (sent < size) {
      std::size_t n = 0;
      const auto rc = curl_easy_send(curl, data + sent, size - sent, &n);
      if (rc == CURLE_AGAIN) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        continue;
      }
      if (rc != CURLE_OK) throw std::runtime_error("DERP TLS send failed: " + curl_error(rc));
      if (n == 0U) throw std::runtime_error("DERP TLS connection closed while writing");
      sent += n;
    }
  }

  void send_all(const std::vector<std::uint8_t>& data) { send_all(data.data(), data.size()); }

  void send_text(const std::string& data) {
    send_all(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  }

  std::optional<DerpFrame> take_buffered_frame() {
    constexpr std::size_t header_size = 5U;
    constexpr std::uint32_t max_frame_size = 10U * 1024U * 1024U;
    if (receive_buffer.size() < header_size) return std::nullopt;

    const std::uint32_t len = (static_cast<std::uint32_t>(receive_buffer[1]) << 24U) |
                              (static_cast<std::uint32_t>(receive_buffer[2]) << 16U) |
                              (static_cast<std::uint32_t>(receive_buffer[3]) << 8U) |
                              static_cast<std::uint32_t>(receive_buffer[4]);
    if (len > max_frame_size) throw std::runtime_error("DERP frame exceeds safety limit");
    const auto payload_size = static_cast<std::size_t>(len);
    if (payload_size > std::numeric_limits<std::size_t>::max() - header_size) {
      throw std::runtime_error("DERP frame length overflow");
    }
    const auto frame_size = header_size + payload_size;
    if (receive_buffer.size() < frame_size) return std::nullopt;

    DerpFrame frame;
    frame.type = static_cast<DerpFrameType>(receive_buffer[0]);
    frame.payload.assign(receive_buffer.begin() + static_cast<std::ptrdiff_t>(header_size),
                         receive_buffer.begin() + static_cast<std::ptrdiff_t>(frame_size));
    receive_buffer.erase(receive_buffer.begin(),
                         receive_buffer.begin() + static_cast<std::ptrdiff_t>(frame_size));
    return frame;
  }

  bool receive_some(std::optional<Clock::time_point> deadline) {
    std::array<std::uint8_t, 16U * 1024U> temp{};
    for (;;) {
      std::size_t n = 0;
      const auto rc = curl_easy_recv(curl, temp.data(), temp.size(), &n);
      if (rc == CURLE_OK) {
        if (n == 0U) throw std::runtime_error("DERP TLS connection closed while reading");
        receive_buffer.insert(receive_buffer.end(), temp.begin(),
                              temp.begin() + static_cast<std::ptrdiff_t>(n));
        return true;
      }
      if (rc != CURLE_AGAIN) {
        throw std::runtime_error("DERP TLS receive failed: " + curl_error(rc));
      }
      if (deadline && Clock::now() >= *deadline) return false;
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
  }

  std::optional<DerpFrame> read_frame_for(std::chrono::milliseconds timeout) {
    if (timeout.count() < 0) throw std::invalid_argument("negative DERP frame timeout");
    const auto deadline = Clock::now() + timeout;
    for (;;) {
      if (auto frame = take_buffered_frame()) return frame;
      if (Clock::now() >= deadline) return std::nullopt;
      if (!receive_some(deadline)) return std::nullopt;
    }
  }

  DerpFrame read_frame() {
    for (;;) {
      if (auto frame = take_buffered_frame()) return std::move(*frame);
      (void)receive_some(std::nullopt);
    }
  }

  void write_frame(DerpFrameType type, const std::vector<std::uint8_t>& payload) {
    send_all(encode_derp_frame(type, payload));
  }

  void connect() {
    close();
    curl_global_once();
    curl = curl_easy_init();
    if (curl == nullptr) throw std::runtime_error("curl_easy_init failed");

    try {
      const auto url = std::string(node.insecure_for_tests ? "http://" : "https://") + authority() + "/";
      setopt(CURLOPT_URL, url.c_str());
      setopt(CURLOPT_CONNECT_ONLY, 1L);
      setopt(CURLOPT_CONNECTTIMEOUT_MS, 10000L);
      setopt(CURLOPT_NOSIGNAL, 1L);
      setopt(CURLOPT_TCP_KEEPALIVE, 1L);
      setopt(CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_1_1));
      if (!node.insecure_for_tests) {
        setopt(CURLOPT_SSL_VERIFYPEER, 1L);
        setopt(CURLOPT_SSL_VERIFYHOST, 2L);
      }

      const auto rc = curl_easy_perform(curl);
      if (rc != CURLE_OK) throw std::runtime_error("DERP TLS connect failed: " + curl_error(rc));

      std::string request = "GET /derp HTTP/1.1\r\nHost: " + authority() +
                            "\r\nConnection: Upgrade\r\nUpgrade: DERP\r\nDerp-Fast-Start: 1\r\n"
                            "User-Agent: tailcat-cpp\r\n\r\n";
      send_text(request);

      const auto greeting = read_frame();
      if (greeting.type != DerpFrameType::ServerKey) {
        throw std::runtime_error("DERP server did not send ServerKey first");
      }
      server_public = parse_derp_server_key(greeting.payload);

      write_frame(DerpFrameType::ClientInfo,
                  make_derp_client_info(identity, server_public, app_name, true));
      const auto info = read_frame();
      if (info.type != DerpFrameType::ServerInfo) {
        throw std::runtime_error("DERP server did not send ServerInfo after ClientInfo");
      }
      (void)open_derp_server_info(identity, server_public, info.payload);
      is_connected = true;
    } catch (...) {
      close();
      throw;
    }
  }
};

DerpHttpClient::DerpHttpClient(DerpNode node, NodeKeyPair identity, std::string app_name)
    : impl_(std::make_unique<Impl>(std::move(node), std::move(identity), std::move(app_name))) {}

DerpHttpClient::~DerpHttpClient() = default;
DerpHttpClient::DerpHttpClient(DerpHttpClient&&) noexcept = default;
DerpHttpClient& DerpHttpClient::operator=(DerpHttpClient&&) noexcept = default;

void DerpHttpClient::connect() { impl_->connect(); }
void DerpHttpClient::close() noexcept { impl_->close(); }
bool DerpHttpClient::connected() const noexcept { return impl_->is_connected; }
const Key32& DerpHttpClient::server_public_key() const {
  if (!impl_->is_connected) throw std::runtime_error("DERP client is not connected");
  return impl_->server_public;
}

void DerpHttpClient::send_packet(const Key32& destination,
                                 const std::vector<std::uint8_t>& packet) {
  if (!impl_->is_connected) throw std::runtime_error("DERP client is not connected");
  impl_->write_frame(DerpFrameType::SendPacket, make_derp_send_packet(destination, packet));
}

void DerpHttpClient::send_pong(const std::array<std::uint8_t, 8>& value) {
  if (!impl_->is_connected) throw std::runtime_error("DERP client is not connected");
  const std::vector<std::uint8_t> payload(value.begin(), value.end());
  impl_->write_frame(DerpFrameType::Pong, payload);
}

std::optional<DerpFrame> DerpHttpClient::receive_for(std::chrono::milliseconds timeout) {
  if (!impl_->is_connected) throw std::runtime_error("DERP client is not connected");
  return impl_->read_frame_for(timeout);
}

DerpFrame DerpHttpClient::receive() {
  if (!impl_->is_connected) throw std::runtime_error("DERP client is not connected");
  return impl_->read_frame();
}

}  // namespace tailcat
