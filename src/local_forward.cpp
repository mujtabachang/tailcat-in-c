// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/local_forward.hpp"

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

struct LocalTcpForwarder::Impl {
  struct AcceptedQueue {
    std::mutex mutex;
    std::deque<std::shared_ptr<HostTcpStream>> sockets;
    bool stopped = false;
    std::string error;
  };

  struct Listener {
    TcpForwardMapping mapping;
    std::shared_ptr<HostTcpListener> listener;
    std::shared_ptr<AcceptedQueue> accepted;
  };

  struct Connection {
    std::shared_ptr<HostTcpStream> host;
    std::shared_ptr<HostReadState> host_read;
    std::shared_ptr<LwipTcpStream> tunnel;
    std::vector<std::uint8_t> pending_to_tunnel;
    std::size_t pending_offset = 0U;
    bool tunnel_write_shutdown = false;
    bool host_write_shutdown = false;
    bool finished = false;
  };

  TailcatClientDataPlane& data;
  std::string bind_address;
  std::vector<TcpForwardMapping> configured;
  std::vector<Listener> listeners;
  std::vector<Connection> connections;

  Impl(TailcatClientDataPlane& data_plane,
       std::vector<TcpForwardMapping> mappings, std::string bind)
      : data(data_plane), bind_address(std::move(bind)), configured(std::move(mappings)) {
    if (configured.empty()) throw std::invalid_argument("forward requires at least one port mapping");
    for (const auto& mapping : configured) {
      if (mapping.local_port == 0U || mapping.remote_port == 0U) {
        throw std::invalid_argument("forward ports must be non-zero");
      }
      auto listener = std::make_shared<HostTcpListener>(
          HostTcpListener::listen(bind_address, mapping.local_port));
      auto accepted = std::make_shared<AcceptedQueue>();
      listeners.push_back(Listener{mapping, listener, accepted});
      std::thread([listener, accepted] {
        try {
          for (;;) {
            auto socket = listener->accept();
            std::lock_guard<std::mutex> lock(accepted->mutex);
            if (accepted->stopped) {
              socket->close();
              return;
            }
            accepted->sockets.push_back(std::move(socket));
          }
        } catch (const std::exception& e) {
          std::lock_guard<std::mutex> lock(accepted->mutex);
          if (!accepted->stopped) accepted->error = e.what();
        }
      }).detach();
    }
  }

  ~Impl() {
    for (auto& listener : listeners) {
      {
        std::lock_guard<std::mutex> lock(listener.accepted->mutex);
        listener.accepted->stopped = true;
      }
      listener.listener->close();
    }
    for (auto& connection : connections) {
      connection.host->close();
      connection.tunnel->close();
    }
  }

  void accept_new() {
    for (auto& listening : listeners) {
      std::deque<std::shared_ptr<HostTcpStream>> accepted;
      std::string error;
      {
        std::lock_guard<std::mutex> lock(listening.accepted->mutex);
        accepted.swap(listening.accepted->sockets);
        error = listening.accepted->error;
      }
      if (!error.empty()) {
        throw std::runtime_error("local TCP listener failed: " + error);
      }
      while (!accepted.empty()) {
        auto host = std::move(accepted.front());
        accepted.pop_front();
        try {
          auto tunnel = data.dial(listening.mapping.remote_port);
          auto reader = start_host_reader(host);
          connections.push_back(Connection{std::move(host), std::move(reader),
                                           std::move(tunnel)});
        } catch (...) {
          host->close();
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
        connection.tunnel->connected() && !connection.tunnel_write_shutdown) {
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
      if (connection.tunnel->connected()) {
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

LocalTcpForwarder::LocalTcpForwarder(TailcatClientDataPlane& data_plane,
                                     std::vector<TcpForwardMapping> mappings,
                                     std::string bind_address)
    : impl_(std::make_unique<Impl>(data_plane, std::move(mappings),
                                   std::move(bind_address))) {}
LocalTcpForwarder::~LocalTcpForwarder() = default;
void LocalTcpForwarder::poll() { impl_->poll(); }
std::size_t LocalTcpForwarder::connection_count() const noexcept {
  return impl_->connections.size();
}
const std::vector<TcpForwardMapping>& LocalTcpForwarder::mappings() const noexcept {
  return impl_->configured;
}

}  // namespace tailcat
