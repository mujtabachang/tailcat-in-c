#pragma once

#include "tailcat/address.hpp"
#include "tailcat/crypto.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace tailcat {

struct DerpPacket {
  Key32 source{};
  std::vector<std::uint8_t> payload;
};

class DerpClient {
 public:
  DerpClient(KeyPair keypair, DerpNode node);
  ~DerpClient();

  DerpClient(const DerpClient&) = delete;
  DerpClient& operator=(const DerpClient&) = delete;

  void connect();
  void close();
  void send_to(const Key32& destination, std::span<const std::uint8_t> payload);
  DerpPacket receive();

  const KeyPair& keypair() const { return keypair_; }

 private:
  std::pair<std::uint8_t, std::vector<std::uint8_t>> read_frame();
  void write_frame(std::uint8_t type, std::span<const std::uint8_t> payload);
  void write_raw(std::span<const std::uint8_t> bytes);
  void read_exact(std::span<std::uint8_t> bytes);
  void handle_server_info(std::span<const std::uint8_t> payload);

  KeyPair keypair_;
  DerpNode node_;
  boost::asio::io_context io_;
  boost::asio::ssl::context ssl_ctx_;
  using SslStream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
  std::unique_ptr<SslStream> stream_;
  std::mutex write_mu_;
  Key32 server_key_{};
  bool connected_ = false;
};

struct DerpMapSelection {
  std::int64_t region_id = 0;
  std::vector<DerpNode> nodes;
};

DerpMapSelection fetch_derp_selection(std::string_view map_url,
                                      std::string_view mode,
                                      std::optional<std::int64_t> wanted_region = std::nullopt);

}  // namespace tailcat
