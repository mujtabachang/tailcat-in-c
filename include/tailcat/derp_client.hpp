#pragma once

#include "tailcat/crypto.hpp"
#include "tailcat/protocol.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace tailcat {

struct DerpReceivedPacket {
  Key32 source{};
  std::vector<std::uint8_t> data;
};

class DerpClient {
 public:
  explicit DerpClient(NodeKeyPair identity);
  ~DerpClient();

  DerpClient(const DerpClient&) = delete;
  DerpClient& operator=(const DerpClient&) = delete;
  DerpClient(DerpClient&&) noexcept;
  DerpClient& operator=(DerpClient&&) noexcept;

  void connect(const DerpNode& node);
  void close() noexcept;
  bool connected() const noexcept;

  const Key32& public_key() const noexcept;
  const Key32& server_public_key() const;

  void send_packet(const Key32& destination, std::span<const std::uint8_t> packet);
  std::optional<DerpReceivedPacket> receive_packet(std::chrono::milliseconds timeout);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tailcat
