// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/port_forward.hpp"

#include "tailcat/host_tcp.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace tailcat {
namespace {

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

}  // namespace

struct ServedTcpPorts::Impl {
  struct Listener {
    std::uint16_t port = 0;
    std::shared_ptr<LwipTcpListener> listener;
  };

  struct Connection {
    std::shared_ptr<LwipTcpStream> tunnel;
    std::shared_ptr<HostTcpStream> host;
    std::shared_ptr<HostReadState> host_read;
    std::vector<std::uint8_t> pending_to_tunnel;
    std::size_t pending_offset = 0U;
    bool tunnel_write_shutdown = false;
    bool host_write_shutdown = false;
    bool finished = false;
  };

  TailcatServerDataPlane& data;
  std::string host_name;
  std::vector<std::uint16_t> exposed_ports;
  std::vector<Listener> listeners;
  std::vector<Connection> connections;

  Impl(TailcatServerDataPlane& data_plane, std::vector<std::uint16_t> ports,
       std::string host)
      : data(data_plane), host_name(std::move(host)), exposed_ports(std::move(ports)) {
    if (exposed_ports.empty()) {
      throw std::invalid_argument("serve requires at least one TCP port");
    }
    std::sort(exposed_ports.begin(), exposed_ports.end());
    if (std::adjacent_find(exposed_ports.begin(), exposed_ports.end()) != exposed_ports.end()) {
      throw std::invalid_argument("duplicate served TCP port");
    }
    for (const auto port : exposed_ports) {
      if (port == 0U) throw std::invalid_argument("cannot serve TCP port zero");
      listeners.push_back(Listener{port, data.listen(port)});
    }
  }

  void accept_new() {
    for (auto& listening : listeners) {
      for (;;) {
        auto tunnel = listening.listener->accept();
        if (!tunnel) break;
        try {
          auto host = HostTcpStream::connect(host_name, listening.port);
          auto reader = start_host_reader(host);
          connections.push_back(Connection{std::move(tunnel), std::move(host),
                                           std::move(reader)});
        } catch (...) {
          tunnel->close();
          // A local target being temporarily unavailable must not take down the
          // Tailcat server or other served ports.
        }
      }
    }
  }

  void take_host_chunk(Connection& connection) {
    if (connection.pending_offset != connection.pending_to_tunnel.size()) return;
    connection.pending_to_tunnel.clear();
    connection.pending_offset = 0U;

    bool host_eof = false;
    std::string host_error;
    {
      std::lock_guard<std::mutex> lock(connection.host_read->mutex);
      if (!connection.host_read->chunks.empty()) {
        connection.pending_to_tunnel =
            std::move(connection.host_read->chunks.front());
        connection.host_read->chunks.pop_front();
      }
      host_eof = connection.host_read->eof;
      host_error = connection.host_read->error;
    }
    if (!host_error.empty()) {
      connection.tunnel->close();
      connection.host->close();
      connection.finished = true;
      return;
    }
    if (connection.pending_to_tunnel.empty() && host_eof &&
        !connection.tunnel_write_shutdown) {
      try {
        connection.tunnel->shutdown_write();
        connection.tunnel_write_shutdown = true;
      } catch (...) {
        connection.tunnel->close();
        connection.host->close();
        connection.finished = true;
      }
    }
  }

  void service(Connection& connection) {
    if (connection.finished) return;
    if (connection.tunnel->failed()) {
      connection.host->close();
      connection.tunnel->close();
      connection.finished = true;
      return;
    }

    try {
      auto from_tunnel = connection.tunnel->read_available();
      if (!from_tunnel.empty()) connection.host->write_all(from_tunnel);

      take_host_chunk(connection);
      if (connection.finished) return;
      if (connection.pending_offset < connection.pending_to_tunnel.size()) {
        const std::span<const std::uint8_t> remaining(
            connection.pending_to_tunnel.data() + connection.pending_offset,
            connection.pending_to_tunnel.size() - connection.pending_offset);
        connection.pending_offset += connection.tunnel->write(remaining);
      }

      if (connection.tunnel->eof() && !connection.host_write_shutdown) {
        connection.host->shutdown_write();
        connection.host_write_shutdown = true;
      }

      bool host_eof = false;
      bool no_host_chunks = false;
      {
        std::lock_guard<std::mutex> lock(connection.host_read->mutex);
        host_eof = connection.host_read->eof;
        no_host_chunks = connection.host_read->chunks.empty();
      }
      if (connection.tunnel->eof() && host_eof && no_host_chunks &&
          connection.pending_offset == connection.pending_to_tunnel.size()) {
        connection.tunnel->close();
        connection.host->close();
        connection.finished = true;
      }
    } catch (...) {
      connection.tunnel->close();
      connection.host->close();
      connection.finished = true;
    }
  }

  void poll() {
    accept_new();
    for (auto& connection : connections) service(connection);
    connections.erase(
        std::remove_if(connections.begin(), connections.end(),
                       [](const Connection& c) { return c.finished; }),
        connections.end());
  }
};

ServedTcpPorts::ServedTcpPorts(TailcatServerDataPlane& data_plane,
                               std::vector<std::uint16_t> ports,
                               std::string host)
    : impl_(std::make_unique<Impl>(data_plane, std::move(ports),
                                   std::move(host))) {}

ServedTcpPorts::~ServedTcpPorts() = default;

void ServedTcpPorts::poll() { impl_->poll(); }
std::size_t ServedTcpPorts::connection_count() const noexcept {
  return impl_->connections.size();
}
const std::vector<std::uint16_t>& ServedTcpPorts::ports() const noexcept {
  return impl_->exposed_ports;
}

}  // namespace tailcat
