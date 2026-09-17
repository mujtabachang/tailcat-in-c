// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/socks_command.hpp"

#include "tailcat/crypto.hpp"
#include "tailcat/data_plane.hpp"
#include "tailcat/derp_http.hpp"
#include "tailcat/derp_map.hpp"
#include "tailcat/host_tcp.hpp"
#include "tailcat/protocol.hpp"
#include "tailcat/saved_key.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace tailcat {
namespace {

using namespace std::chrono_literals;
constexpr std::string_view kDefaultDerpMap = "https://tailcat.dev/derpmap.json";

std::uint16_t parse_port(std::string_view text, bool allow_zero) {
  if (text.empty()) throw std::invalid_argument("empty SOCKS listen port");
  std::size_t consumed = 0U;
  const auto value = std::stoul(std::string(text), &consumed, 10);
  if (consumed != text.size() || value > 65535U || (!allow_zero && value == 0U)) {
    throw std::invalid_argument("invalid port: " + std::string(text));
  }
  return static_cast<std::uint16_t>(value);
}

bool decimal_only(std::string_view value) {
  return !value.empty() &&
         std::all_of(value.begin(), value.end(), [](unsigned char c) {
           return std::isdigit(c) != 0;
         });
}

std::string lower_ascii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

NodeKeyPair client_identity(std::string_view key_name) {
  if (key_name == "new") return generate_node_key();
  if (!key_name.empty()) return load_saved_tailcat_key(std::string(key_name)).identity;
  if (saved_tailcat_key_exists("client-default")) {
    return load_saved_tailcat_key("client-default").identity;
  }
  return generate_node_key();
}

DerpRegion resolve_region(const ConnInfo& info) {
  if (!info.regions.empty()) {
    if (info.region_id != 0) {
      for (const auto& region : info.regions) {
        if (region.region_id == info.region_id) return region;
      }
    }
    return info.regions.front();
  }
  if (info.region_id == 0) {
    throw std::runtime_error("tailcat address contains no DERP region");
  }
  return region_by_id(fetch_derp_map(std::string(kDefaultDerpMap)), info.region_id);
}

std::vector<std::uint8_t> read_exact(const std::shared_ptr<HostTcpStream>& stream,
                                     std::size_t size) {
  std::vector<std::uint8_t> out;
  out.reserve(size);
  while (out.size() < size) {
    auto part = stream->read_some(size - out.size());
    if (part.empty()) throw std::runtime_error("unexpected EOF in SOCKS5 handshake");
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

void socks_reply(const std::shared_ptr<HostTcpStream>& stream, std::uint8_t code) {
  const std::array<std::uint8_t, 10> reply = {
      0x05U, code, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
  stream->write_all(reply);
}

struct HostReadState {
  std::mutex mutex;
  std::deque<std::vector<std::uint8_t>> chunks;
  bool eof = false;
  std::string error;
};

std::shared_ptr<HostReadState> start_host_reader(
    const std::shared_ptr<HostTcpStream>& host) {
  auto state = std::make_shared<HostReadState>();
  std::thread([host, state] {
    try {
      for (;;) {
        auto chunk = host->read_some();
        if (chunk.empty()) {
          std::lock_guard<std::mutex> lock(state->mutex);
          state->eof = true;
          break;
        }
        std::lock_guard<std::mutex> lock(state->mutex);
        state->chunks.push_back(std::move(chunk));
      }
    } catch (const std::exception& e) {
      std::lock_guard<std::mutex> lock(state->mutex);
      state->error = e.what();
      state->eof = true;
    }
  }).detach();
  return state;
}

class SocksProxy {
 public:
  SocksProxy(TailcatClientDataPlane& data, std::string bind_host,
             std::uint16_t bind_port, std::string server_address)
      : data_(data),
        server_address_(std::move(server_address)),
        listener_(std::make_shared<HostTcpListener>(
            HostTcpListener::listen(bind_host, bind_port))),
        accepted_(std::make_shared<AcceptedQueue>()),
        handshakes_(std::make_shared<HandshakeQueue>()) {
    bind_host_ = std::move(bind_host);
    std::thread([listener = listener_, queue = accepted_] {
      try {
        for (;;) {
          auto socket = listener->accept();
          std::lock_guard<std::mutex> lock(queue->mutex);
          if (queue->stopped) {
            socket->close();
            return;
          }
          queue->sockets.push_back(std::move(socket));
        }
      } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(queue->mutex);
        if (!queue->stopped) queue->error = e.what();
      }
    }).detach();
  }

  ~SocksProxy() {
    {
      std::lock_guard<std::mutex> lock(accepted_->mutex);
      accepted_->stopped = true;
    }
    {
      std::lock_guard<std::mutex> lock(handshakes_->mutex);
      handshakes_->stopped = true;
    }
    listener_->close();
    for (auto& connection : connections_) {
      connection.host->close();
      connection.tunnel->close();
    }
  }

  std::uint16_t port() const noexcept { return listener_->port(); }
  const std::string& host() const noexcept { return bind_host_; }

  void poll() {
    accept_new();
    adopt_handshakes();
    for (auto& connection : connections_) service(connection);
    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
                       [](const Connection& c) { return c.finished; }),
        connections_.end());
  }

 private:
  struct AcceptedQueue {
    std::mutex mutex;
    std::deque<std::shared_ptr<HostTcpStream>> sockets;
    bool stopped = false;
    std::string error;
  };

  struct HandshakeResult {
    std::shared_ptr<HostTcpStream> host;
    std::uint16_t port = 0U;
  };

  struct HandshakeQueue {
    std::mutex mutex;
    std::deque<HandshakeResult> ready;
    bool stopped = false;
  };

  struct Connection {
    std::shared_ptr<HostTcpStream> host;
    std::shared_ptr<LwipTcpStream> tunnel;
    std::shared_ptr<HostReadState> host_read;
    std::vector<std::uint8_t> pending_to_tunnel;
    std::size_t pending_offset = 0U;
    bool replied = false;
    bool tunnel_write_shutdown = false;
    bool host_write_shutdown = false;
    bool finished = false;
  };

  void begin_handshake(const std::shared_ptr<HostTcpStream>& host) {
    auto queue = handshakes_;
    const auto server_address = server_address_;
    std::thread([host, queue, server_address] {
      try {
        const auto greeting = read_exact(host, 2U);
        if (greeting[0] != 0x05U || greeting[1] == 0U) {
          throw std::runtime_error("invalid SOCKS5 greeting");
        }
        const auto methods = read_exact(host, greeting[1]);
        if (std::find(methods.begin(), methods.end(), 0x00U) == methods.end()) {
          const std::array<std::uint8_t, 2> response = {0x05U, 0xffU};
          host->write_all(response);
          host->close();
          return;
        }
        const std::array<std::uint8_t, 2> response = {0x05U, 0x00U};
        host->write_all(response);

        const auto header = read_exact(host, 4U);
        if (header[0] != 0x05U || header[2] != 0x00U) {
          throw std::runtime_error("invalid SOCKS5 request");
        }
        if (header[1] != 0x01U) {
          socks_reply(host, 0x07U);
          host->close();
          return;
        }

        std::string target_host;
        if (header[3] == 0x01U) {
          const auto address = read_exact(host, 4U);
          target_host = std::to_string(address[0]) + "." +
                        std::to_string(address[1]) + "." +
                        std::to_string(address[2]) + "." +
                        std::to_string(address[3]);
        } else if (header[3] == 0x03U) {
          const auto length = read_exact(host, 1U)[0];
          const auto name = read_exact(host, length);
          target_host.assign(name.begin(), name.end());
        } else if (header[3] == 0x04U) {
          (void)read_exact(host, 16U);
          target_host = "<ipv6>";
        } else {
          socks_reply(host, 0x08U);
          host->close();
          return;
        }
        const auto port_bytes = read_exact(host, 2U);
        const auto port = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(port_bytes[0]) << 8U) |
            static_cast<std::uint16_t>(port_bytes[1]));
        if (port == 0U) {
          socks_reply(host, 0x01U);
          host->close();
          return;
        }

        const auto lowered = lower_ascii(target_host);
        if (lowered != "server.tailcat" && target_host != server_address) {
          socks_reply(host, 0x04U);
          host->close();
          return;
        }

        std::lock_guard<std::mutex> lock(queue->mutex);
        if (queue->stopped) {
          host->close();
          return;
        }
        queue->ready.push_back(HandshakeResult{host, port});
      } catch (...) {
        host->close();
      }
    }).detach();
  }

  void accept_new() {
    std::deque<std::shared_ptr<HostTcpStream>> sockets;
    std::string error;
    {
      std::lock_guard<std::mutex> lock(accepted_->mutex);
      sockets.swap(accepted_->sockets);
      error = accepted_->error;
    }
    if (!error.empty()) throw std::runtime_error("SOCKS5 listener failed: " + error);
    while (!sockets.empty()) {
      auto socket = std::move(sockets.front());
      sockets.pop_front();
      begin_handshake(socket);
    }
  }

  void adopt_handshakes() {
    std::deque<HandshakeResult> ready;
    {
      std::lock_guard<std::mutex> lock(handshakes_->mutex);
      ready.swap(handshakes_->ready);
    }
    while (!ready.empty()) {
      auto item = std::move(ready.front());
      ready.pop_front();
      try {
        auto tunnel = data_.dial(item.port);
        connections_.push_back(Connection{std::move(item.host), std::move(tunnel)});
      } catch (...) {
        try {
          socks_reply(item.host, 0x01U);
        } catch (...) {
        }
        item.host->close();
      }
    }
  }

  void take_host_chunk(Connection& connection) {
    if (!connection.host_read ||
        connection.pending_offset != connection.pending_to_tunnel.size()) {
      return;
    }
    connection.pending_to_tunnel.clear();
    connection.pending_offset = 0U;
    bool eof = false;
    std::string error;
    {
      std::lock_guard<std::mutex> lock(connection.host_read->mutex);
      if (!connection.host_read->chunks.empty()) {
        connection.pending_to_tunnel =
            std::move(connection.host_read->chunks.front());
        connection.host_read->chunks.pop_front();
      }
      eof = connection.host_read->eof;
      error = connection.host_read->error;
    }
    if (!error.empty()) {
      connection.finished = true;
      return;
    }
    if (connection.pending_to_tunnel.empty() && eof &&
        !connection.tunnel_write_shutdown) {
      connection.tunnel->shutdown_write();
      connection.tunnel_write_shutdown = true;
    }
  }

  void service(Connection& connection) {
    if (connection.finished) return;
    try {
      if (connection.tunnel->failed()) {
        if (!connection.replied) socks_reply(connection.host, 0x05U);
        connection.finished = true;
      } else if (connection.tunnel->connected()) {
        if (!connection.replied) {
          socks_reply(connection.host, 0x00U);
          connection.replied = true;
          connection.host_read = start_host_reader(connection.host);
        }

        const auto received = connection.tunnel->read_available();
        if (!received.empty()) connection.host->write_all(received);
        take_host_chunk(connection);
        if (!connection.finished &&
            connection.pending_offset < connection.pending_to_tunnel.size()) {
          const std::span<const std::uint8_t> remaining(
              connection.pending_to_tunnel.data() + connection.pending_offset,
              connection.pending_to_tunnel.size() - connection.pending_offset);
          connection.pending_offset += connection.tunnel->write(remaining);
        }
        if (connection.tunnel->eof() && !connection.host_write_shutdown) {
          connection.host->shutdown_write();
          connection.host_write_shutdown = true;
        }
      }

      if (connection.replied && connection.host_read) {
        bool host_eof = false;
        bool no_chunks = false;
        {
          std::lock_guard<std::mutex> lock(connection.host_read->mutex);
          host_eof = connection.host_read->eof;
          no_chunks = connection.host_read->chunks.empty();
        }
        if (connection.tunnel->eof() && host_eof && no_chunks &&
            connection.pending_offset == connection.pending_to_tunnel.size()) {
          connection.finished = true;
        }
      }
    } catch (...) {
      connection.finished = true;
    }

    if (connection.finished) {
      connection.tunnel->close();
      connection.host->close();
    }
  }

  TailcatClientDataPlane& data_;
  std::string server_address_;
  std::string bind_host_;
  std::shared_ptr<HostTcpListener> listener_;
  std::shared_ptr<AcceptedQueue> accepted_;
  std::shared_ptr<HandshakeQueue> handshakes_;
  std::vector<Connection> connections_;
};

}  // namespace

SocksListenAddress parse_socks_listen_address(std::string_view value) {
  if (value.empty()) value = "127.0.0.1:0";
  if (decimal_only(value)) {
    return SocksListenAddress{"127.0.0.1", parse_port(value, true)};
  }
  if (value.front() == '[') {
    const auto close = value.find(']');
    if (close == std::string_view::npos) {
      throw std::invalid_argument("invalid bracketed SOCKS listen address");
    }
    const std::string host(value.substr(1U, close - 1U));
    if (close + 1U == value.size()) return SocksListenAddress{host, 0U};
    if (value[close + 1U] != ':') {
      throw std::invalid_argument("invalid bracketed SOCKS listen address");
    }
    return SocksListenAddress{host, parse_port(value.substr(close + 2U), true)};
  }
  const auto first_colon = value.find(':');
  if (first_colon == std::string_view::npos) {
    return SocksListenAddress{std::string(value), 0U};
  }
  if (value.find(':', first_colon + 1U) != std::string_view::npos) {
    return SocksListenAddress{std::string(value), 0U};
  }
  return SocksListenAddress{std::string(value.substr(0U, first_colon)),
                            parse_port(value.substr(first_colon + 1U), true)};
}

int run_socks_command(const std::vector<std::string>& args, bool verbose,
                      std::string_view key_name) {
  std::string listen = "127.0.0.1:0";
  std::string address;
  for (std::size_t i = 0; i < args.size(); ++i) {
    const auto& arg = args[i];
    if (arg == "--listen") {
      if (++i >= args.size()) throw std::invalid_argument("--listen requires a value");
      listen = args[i];
    } else if (arg.rfind("--listen=", 0) == 0) {
      listen = arg.substr(9U);
    } else if (address.empty() && !arg.empty() && arg[0] != '-') {
      address = arg;
    } else {
      throw std::invalid_argument(
          "native socks currently takes one fixed <tc-address> and no child command");
    }
  }
  if (address.empty()) {
    throw std::invalid_argument("socks requires a fixed <tc-address>");
  }

  auto info = parse_tailcat_addr(address);
  const auto region = resolve_region(info);
  const auto node = primary_derp_node(region);
  const auto identity = client_identity(key_name);
  DerpHttpClient derp(node, identity, "tailcat");
  derp.connect();
  TailcatClientDataPlane data(derp, identity, std::move(info));
  data.connect(15s);

  const auto bind = parse_socks_listen_address(listen);
  SocksProxy proxy(data, bind.host, bind.port, address);
  std::cerr << "# SOCKS5 listening on "
            << (proxy.host().empty() ? std::string("0.0.0.0") : proxy.host())
            << ':' << proxy.port() << '\n';
  std::cerr << "# use the hostname server.tailcat for services on this Tailcat server\n";
  if (verbose) {
    std::cerr << "# SOCKS tunnel through DERP region " << region.region_id;
    if (!region.region_code.empty()) std::cerr << " (" << region.region_code << ')';
    std::cerr << '\n';
  }

  for (;;) {
    (void)data.pump_for(10ms);
    proxy.poll();
  }
}

}  // namespace tailcat
