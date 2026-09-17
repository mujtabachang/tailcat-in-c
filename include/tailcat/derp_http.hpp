// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/derp.hpp"
#include "tailcat/derp_transport.hpp"
#include "tailcat/protocol.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tailcat {

// A DERP-over-HTTPS client using libcurl only as the verified TLS carrier.
// HTTP upgrade bytes and all DERP protocol framing are implemented by Tailcat.
class DerpHttpClient final : public DerpTransport {
 public:
  DerpHttpClient(DerpNode node, NodeKeyPair identity, std::string app_name);
  ~DerpHttpClient() override;
  DerpHttpClient(const DerpHttpClient&) = delete;
  DerpHttpClient& operator=(const DerpHttpClient&) = delete;
  DerpHttpClient(DerpHttpClient&&) noexcept;
  DerpHttpClient& operator=(DerpHttpClient&&) noexcept;

  void connect();
  void close() noexcept;
  bool connected() const noexcept;
  const Key32& server_public_key() const;

  void send_packet(const Key32& destination,
                   const std::vector<std::uint8_t>& packet) override;
  void send_pong(const std::array<std::uint8_t, 8>& value) override;
  std::optional<DerpFrame> receive_for(std::chrono::milliseconds timeout) override;
  DerpFrame receive();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tailcat
