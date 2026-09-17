#include "tailcat/derp_client.hpp"

#include <nlohmann/json.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tailcat {
namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
#endif

constexpr std::size_t kDerpMaxPacket = 64U << 10;
constexpr std::size_t kMaxFrame = 10U << 20;
constexpr std::array<std::uint8_t, 8> kDerpMagic = {
    0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};

void close_socket(NativeSocket socket) noexcept {
  if (socket == kInvalidSocket) return;
#ifdef _WIN32
  closesocket(socket);
#else
  ::close(socket);
#endif
}

std::string openssl_errors(std::string_view prefix) {
  std::string out(prefix);
  bool first = true;
  while (const auto err = ERR_get_error()) {
    std::array<char, 256> buf{};
    ERR_error_string_n(err, buf.data(), buf.size());
    out += first ? ": " : "; ";
    out += buf.data();
    first = false;
  }
  return out;
}

NativeSocket connect_tcp(const std::string& host, std::uint16_t port) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  const auto port_text = std::to_string(port);
  addrinfo* list = nullptr;
  const int gai = getaddrinfo(host.c_str(), port_text.c_str(), &hints, &list);
  if (gai != 0) {
#ifdef _WIN32
    throw std::runtime_error("DERP DNS lookup failed for " + host + ": " + std::to_string(gai));
#else
    throw std::runtime_error("DERP DNS lookup failed for " + host + ": " + gai_strerror(gai));
#endif
  }

  NativeSocket result = kInvalidSocket;
  for (auto* ai = list; ai != nullptr; ai = ai->ai_next) {
    const auto candidate = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (candidate == kInvalidSocket) continue;
#ifdef _WIN32
    const int addr_len = static_cast<int>(ai->ai_addrlen);
    const int rc = ::connect(candidate, ai->ai_addr, addr_len);
#else
    const int rc = ::connect(candidate, ai->ai_addr, ai->ai_addrlen);
#endif
    if (rc == 0) {
      result = candidate;
      break;
    }
    close_socket(candidate);
  }
  freeaddrinfo(list);
  if (result == kInvalidSocket) throw std::runtime_error("unable to connect to DERP host " + host);
  return result;
}

bool wait_readable(NativeSocket socket, std::chrono::milliseconds timeout) {
  fd_set reads;
  FD_ZERO(&reads);
  FD_SET(socket, &reads);
  timeval tv{};
  const auto total_ms = std::max<std::int64_t>(0, timeout.count());
  tv.tv_sec = static_cast<long>(total_ms / 1000);
  tv.tv_usec = static_cast<long>((total_ms % 1000) * 1000);
#ifdef _WIN32
  const int rc = select(0, &reads, nullptr, nullptr, &tv);
#else
  const int rc = select(socket + 1, &reads, nullptr, nullptr, &tv);
#endif
  if (rc < 0) throw std::runtime_error("DERP socket select failed");
  return rc > 0;
}

struct Frame {
  DerpFrameType type{};
  std::vector<std::uint8_t> body;
};

}  // namespace

struct DerpClient::Impl {
  explicit Impl(NodeKeyPair pair) : identity(std::move(pair)) {}

  NodeKeyPair identity;
  Key32 server_public{};
  NativeSocket socket = kInvalidSocket;
  SSL_CTX* ssl_ctx = nullptr;
  SSL* ssl = nullptr;
  std::vector<std::uint8_t> buffered;
  bool is_connected = false;

  ~Impl() { close(); }

  void close() noexcept {
    is_connected = false;
    if (ssl != nullptr) {
      SSL_free(ssl);
      ssl = nullptr;
    }
    if (ssl_ctx != nullptr) {
      SSL_CTX_free(ssl_ctx);
      ssl_ctx = nullptr;
    }
    close_socket(socket);
    socket = kInvalidSocket;
    buffered.clear();
    server_public.fill(0);
  }

  void tls_connect(const DerpNode& node) {
    const std::string host = node.host_name;
    if (host.empty()) throw std::runtime_error("DERP node has no host name");
    const auto port_value = node.derp_port == 0 ? 443 : node.derp_port;
    if (port_value < 1 || port_value > 65535) throw std::runtime_error("invalid DERP port");
    socket = connect_tcp(host, static_cast<std::uint16_t>(port_value));

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ssl_ctx == nullptr) throw std::runtime_error(openssl_errors("SSL_CTX_new failed"));
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
      throw std::runtime_error(openssl_errors("unable to load system CA roots"));
    }

    ssl = SSL_new(ssl_ctx);
    if (ssl == nullptr) throw std::runtime_error(openssl_errors("SSL_new failed"));
    if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) {
      throw std::runtime_error(openssl_errors("unable to set DERP TLS SNI"));
    }
    const std::string verify_name = node.cert_name.empty() ? host : node.cert_name;
    if (SSL_set1_host(ssl, verify_name.c_str()) != 1) {
      throw std::runtime_error(openssl_errors("unable to configure DERP certificate hostname"));
    }
#ifdef _WIN32
    if (socket > static_cast<NativeSocket>(std::numeric_limits<int>::max())) {
      throw std::runtime_error("DERP socket handle cannot be represented by OpenSSL");
    }
#endif
    if (SSL_set_fd(ssl, static_cast<int>(socket)) != 1) {
      throw std::runtime_error(openssl_errors("SSL_set_fd failed"));
    }
    if (SSL_connect(ssl) != 1) throw std::runtime_error(openssl_errors("DERP TLS handshake failed"));
    if (SSL_get_verify_result(ssl) != X509_V_OK) throw std::runtime_error("DERP TLS certificate verification failed");
  }

  void write_all(std::span<const std::uint8_t> data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
      const auto remaining = data.size() - offset;
      const int chunk = static_cast<int>(std::min<std::size_t>(remaining, static_cast<std::size_t>(INT_MAX)));
      const int wrote = SSL_write(ssl, data.data() + offset, chunk);
      if (wrote <= 0) throw std::runtime_error(openssl_errors("DERP TLS write failed"));
      offset += static_cast<std::size_t>(wrote);
    }
  }

  void write_text(std::string_view text) {
    write_all(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
  }

  std::vector<std::uint8_t> read_some() {
    std::array<std::uint8_t, 8192> buf{};
    const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
    if (n <= 0) {
      const int ssl_error = SSL_get_error(ssl, n);
      if (ssl_error == SSL_ERROR_ZERO_RETURN) throw std::runtime_error("DERP connection closed");
      throw std::runtime_error(openssl_errors("DERP TLS read failed"));
    }
    return {buf.begin(), buf.begin() + n};
  }

  std::vector<std::uint8_t> read_exact(std::size_t count) {
    std::vector<std::uint8_t> out;
    out.reserve(count);
    while (out.size() < count) {
      if (!buffered.empty()) {
        const auto take = std::min(count - out.size(), buffered.size());
        out.insert(out.end(), buffered.begin(), buffered.begin() + static_cast<std::ptrdiff_t>(take));
        buffered.erase(buffered.begin(), buffered.begin() + static_cast<std::ptrdiff_t>(take));
        continue;
      }
      auto chunk = read_some();
      const auto take = std::min(count - out.size(), chunk.size());
      out.insert(out.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(take));
      if (take < chunk.size()) {
        buffered.insert(buffered.end(), chunk.begin() + static_cast<std::ptrdiff_t>(take), chunk.end());
      }
    }
    return out;
  }

  void http_upgrade(const DerpNode& node) {
    std::string request = "GET /derp HTTP/1.1\r\nHost: " + node.host_name +
                          "\r\nConnection: Upgrade\r\nUpgrade: DERP\r\nUser-Agent: tailcat-cpp\r\n\r\n";
    write_text(request);

    std::vector<std::uint8_t> response;
    constexpr std::string_view marker = "\r\n\r\n";
    std::size_t header_end = std::string::npos;
    while (header_end == std::string::npos) {
      if (response.size() > 64U * 1024U) throw std::runtime_error("DERP HTTP upgrade response is too large");
      auto chunk = read_some();
      response.insert(response.end(), chunk.begin(), chunk.end());
      const std::string_view text(reinterpret_cast<const char*>(response.data()), response.size());
      header_end = text.find(marker);
    }

    const std::string_view headers(reinterpret_cast<const char*>(response.data()), header_end + marker.size());
    const auto first_line_end = headers.find("\r\n");
    if (first_line_end == std::string_view::npos) throw std::runtime_error("invalid DERP HTTP response");
    const auto status_line = headers.substr(0, first_line_end);
    if (status_line.find(" 101 ") == std::string_view::npos && !status_line.ends_with(" 101")) {
      throw std::runtime_error("DERP server refused protocol upgrade: " + std::string(status_line));
    }
    const auto body_start = header_end + marker.size();
    if (body_start < response.size()) {
      buffered.insert(buffered.end(), response.begin() + static_cast<std::ptrdiff_t>(body_start), response.end());
    }
  }

  Frame read_frame() {
    const auto header_bytes = read_exact(5);
    const auto header = decode_derp_frame_header(header_bytes);
    if (header.length > kMaxFrame) throw std::runtime_error("DERP frame exceeds size limit");
    return {header.type, read_exact(header.length)};
  }

  void send_frame(DerpFrameType type, std::span<const std::uint8_t> body) {
    if (body.size() > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("DERP frame is too large");
    const auto header = encode_derp_frame_header(type, static_cast<std::uint32_t>(body.size()));
    write_all(header);
    if (!body.empty()) write_all(body);
  }

  void authenticate() {
    const auto greeting = read_frame();
    if (greeting.type != DerpFrameType::server_key || greeting.body.size() < kDerpMagic.size() + server_public.size()) {
      throw std::runtime_error("invalid DERP server greeting");
    }
    if (!std::equal(kDerpMagic.begin(), kDerpMagic.end(), greeting.body.begin())) {
      throw std::runtime_error("invalid DERP server magic");
    }
    std::copy_n(greeting.body.begin() + static_cast<std::ptrdiff_t>(kDerpMagic.size()), server_public.size(), server_public.begin());

    nlohmann::json info;
    info["version"] = 2;
    info["CanAckPings"] = true;
    info["AppName"] = "tailcat-cpp";
    const auto text = info.dump();
    const auto sealed = nacl_box_seal(
        identity.private_key,
        server_public,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    std::vector<std::uint8_t> body;
    body.reserve(identity.public_key.size() + sealed.size());
    body.insert(body.end(), identity.public_key.begin(), identity.public_key.end());
    body.insert(body.end(), sealed.begin(), sealed.end());
    send_frame(DerpFrameType::client_info, body);

    for (;;) {
      auto frame = read_frame();
      if (frame.type == DerpFrameType::server_info) {
        const auto clear = nacl_box_open(identity.private_key, server_public, frame.body);
        if (!clear) throw std::runtime_error("DERP server info authentication failed");
        try {
          (void)nlohmann::json::parse(clear->begin(), clear->end());
        } catch (const nlohmann::json::exception& e) {
          throw std::runtime_error(std::string("invalid DERP server info JSON: ") + e.what());
        }
        return;
      }
      if (frame.type == DerpFrameType::ping) {
        if (frame.body.size() != 8) throw std::runtime_error("invalid DERP ping length");
        send_frame(DerpFrameType::pong, frame.body);
        continue;
      }
      if (frame.type == DerpFrameType::keep_alive) continue;
      throw std::runtime_error("unexpected DERP frame before server authentication");
    }
  }
};

DerpClient::DerpClient(NodeKeyPair identity) : impl_(std::make_unique<Impl>(std::move(identity))) {}
DerpClient::~DerpClient() = default;
DerpClient::DerpClient(DerpClient&&) noexcept = default;
DerpClient& DerpClient::operator=(DerpClient&&) noexcept = default;

void DerpClient::connect(const DerpNode& node) {
  impl_->close();
  try {
    impl_->tls_connect(node);
    impl_->http_upgrade(node);
    impl_->authenticate();
    impl_->is_connected = true;
  } catch (...) {
    impl_->close();
    throw;
  }
}

void DerpClient::close() noexcept { impl_->close(); }
bool DerpClient::connected() const noexcept { return impl_->is_connected; }
const Key32& DerpClient::public_key() const noexcept { return impl_->identity.public_key; }
const Key32& DerpClient::server_public_key() const {
  if (!impl_->is_connected) throw std::runtime_error("DERP client is not connected");
  return impl_->server_public;
}

void DerpClient::send_packet(const Key32& destination, std::span<const std::uint8_t> packet) {
  if (!impl_->is_connected) throw std::runtime_error("DERP client is not connected");
  if (packet.size() > kDerpMaxPacket) throw std::runtime_error("DERP packet exceeds 64 KiB limit");
  std::vector<std::uint8_t> body;
  body.reserve(destination.size() + packet.size());
  body.insert(body.end(), destination.begin(), destination.end());
  body.insert(body.end(), packet.begin(), packet.end());
  impl_->send_frame(DerpFrameType::send_packet, body);
}

std::optional<DerpReceivedPacket> DerpClient::receive_packet(std::chrono::milliseconds timeout) {
  if (!impl_->is_connected) throw std::runtime_error("DERP client is not connected");
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    if (impl_->buffered.empty() && SSL_pending(impl_->ssl) == 0) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) return std::nullopt;
      const auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
      if (!wait_readable(impl_->socket, remain)) return std::nullopt;
    }

    auto frame = impl_->read_frame();
    switch (frame.type) {
      case DerpFrameType::recv_packet: {
        if (frame.body.size() < 32) throw std::runtime_error("short DERP received-packet frame");
        DerpReceivedPacket packet;
        std::copy_n(frame.body.begin(), packet.source.size(), packet.source.begin());
        packet.data.assign(frame.body.begin() + static_cast<std::ptrdiff_t>(packet.source.size()), frame.body.end());
        return packet;
      }
      case DerpFrameType::ping:
        if (frame.body.size() != 8) throw std::runtime_error("invalid DERP ping length");
        impl_->send_frame(DerpFrameType::pong, frame.body);
        break;
      case DerpFrameType::keep_alive:
      case DerpFrameType::peer_present:
      case DerpFrameType::peer_gone:
      case DerpFrameType::health:
        break;
      case DerpFrameType::server_info: {
        const auto clear = nacl_box_open(impl_->identity.private_key, impl_->server_public, frame.body);
        if (!clear) throw std::runtime_error("DERP server info authentication failed");
        break;
      }
      case DerpFrameType::restarting:
        throw std::runtime_error("DERP server is restarting");
      default:
        break;
    }
  }
}

}  // namespace tailcat
