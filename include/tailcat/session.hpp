#pragma once

#include "tailcat/address.hpp"
#include "tailcat/crypto.hpp"
#include "tailcat/derp.hpp"
#include "tailcat/protocol.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>

namespace tailcat {

class ClientSession;

class Stream : public std::enable_shared_from_this<Stream> {
 public:
  ~Stream();
  void write(std::span<const std::uint8_t> bytes);
  std::vector<std::uint8_t> read();
  void close();
  std::uint32_t id() const { return id_; }

 private:
  friend class ClientSession;
  Stream(ClientSession* owner, std::uint32_t id);
  void push(Message message);

  ClientSession* owner_;
  std::uint32_t id_;
  std::mutex mu_;
  std::condition_variable cv_;
  std::deque<Message> queue_;
  bool closed_ = false;
};

class ClientSession {
 public:
  ClientSession(const ConnInfo& info, KeyPair keypair);
  ~ClientSession();

  void connect();
  std::shared_ptr<Stream> open(std::string target);
  double ping();
  void close();

 private:
  friend class Stream;
  void send_message(const Message& message);
  void receive_loop();
  DerpNode choose_node() const;

  ConnInfo info_;
  KeyPair keypair_;
  Key32 session_key_{};
  std::unique_ptr<DerpClient> derp_;
  std::thread receive_thread_;
  std::mutex streams_mu_;
  std::map<std::uint32_t, std::weak_ptr<Stream>> streams_;
  std::atomic<std::uint32_t> next_stream_{1};
  std::atomic<bool> stopping_{false};
  std::mutex ping_mu_;
  std::condition_variable ping_cv_;
  std::uint64_t last_pong_ = 0;
};

struct ServerOptions {
  std::set<std::uint16_t> allowed_local_ports;
  bool allow_all_local_ports = false;
  bool exit_node = false;
  bool stdio = false;
};

class ServerSession {
 public:
  ServerSession(KeyPair keypair, Key32 preshared_key, DerpNode node, ServerOptions options);
  ~ServerSession();
  void run();
  void close();

 private:
  struct RemoteStream {
    Key32 peer{};
    std::uint32_t id = 0;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
    bool stdio = false;
    std::mutex write_mu;
  };

  std::string stream_key(const Key32& peer, std::uint32_t id) const;
  void send_message(const Key32& peer, const Key32& session_key, const Message& message);
  void handle_message(const Key32& peer, const Key32& session_key, const Message& message);
  void open_target(const Key32& peer, const Key32& session_key, const Message& message);
  void start_socket_reader(std::shared_ptr<RemoteStream> stream, Key32 session_key);
  bool target_allowed(std::string_view host, std::uint16_t port) const;

  KeyPair keypair_;
  Key32 preshared_key_{};
  DerpNode node_;
  ServerOptions options_;
  std::unique_ptr<DerpClient> derp_;
  boost::asio::io_context socket_io_;
  std::mutex streams_mu_;
  std::map<std::string, std::shared_ptr<RemoteStream>> streams_;
  std::atomic<bool> stopping_{false};
  std::mutex stdio_mu_;
};

}  // namespace tailcat
