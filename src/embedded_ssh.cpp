// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/embedded_ssh.hpp"

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace tailcat {
namespace {

namespace fs = std::filesystem;
using namespace std::chrono_literals;

std::string env_value(const char* name) {
  const char* value = std::getenv(name);
  return value == nullptr ? std::string{} : std::string(value);
}

fs::path user_config_root() {
#ifdef _WIN32
  const auto appdata = env_value("APPDATA");
  if (!appdata.empty()) return fs::path(appdata);
  const auto home = env_value("USERPROFILE");
  if (!home.empty()) return fs::path(home) / "AppData" / "Roaming";
#elif defined(__APPLE__)
  const auto home = env_value("HOME");
  if (!home.empty()) return fs::path(home) / "Library" / "Application Support";
#else
  const auto xdg = env_value("XDG_CONFIG_HOME");
  if (!xdg.empty()) return fs::path(xdg);
  const auto home = env_value("HOME");
  if (!home.empty()) return fs::path(home) / ".config";
#endif
  throw std::runtime_error("cannot determine the user configuration directory");
}

std::string ensure_ssh_host_key() {
  static std::mutex key_mutex;
  std::lock_guard<std::mutex> lock(key_mutex);
  const fs::path dir = user_config_root() / "tailcat" / "ssh";
  const fs::path path = dir / "ssh_host_ed25519_key";
  std::error_code ec;
  fs::create_directories(dir, ec);
  if (ec) throw std::runtime_error("failed to create Tailcat SSH key directory: " + ec.message());
  if (fs::exists(path, ec) && !ec) return path.string();
  if (ec) throw std::runtime_error("failed to inspect Tailcat SSH host key: " + ec.message());

  ssh_key key = nullptr;
  if (ssh_pki_generate_key(SSH_KEYTYPE_ED25519, nullptr, &key) != SSH_OK || key == nullptr) {
    throw std::runtime_error("failed to generate Tailcat SSH Ed25519 host key");
  }
  const int rc = ssh_pki_export_privkey_file(key, nullptr, nullptr, nullptr,
                                              path.string().c_str());
  ssh_key_free(key);
  if (rc != SSH_OK) throw std::runtime_error("failed to persist Tailcat SSH host key");
#ifdef _WIN32
  (void)_chmod(path.string().c_str(), _S_IREAD | _S_IWRITE);
#else
  (void)chmod(path.string().c_str(), S_IRUSR | S_IWUSR);
#endif
  return path.string();
}

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
void ensure_winsock() {
  static std::once_flag once;
  std::call_once(once, [] {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      throw std::runtime_error("WSAStartup failed for embedded SSH");
    }
  });
}
void close_native_socket(NativeSocket s) noexcept {
  if (s != kInvalidSocket) closesocket(s);
}
bool socket_would_block() {
  const int e = WSAGetLastError();
  return e == WSAEWOULDBLOCK || e == WSAEINTR;
}
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
void close_native_socket(NativeSocket s) noexcept {
  if (s != kInvalidSocket) close(s);
}
bool socket_would_block() { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
#endif

class OwnedSocket {
 public:
  OwnedSocket() = default;
  explicit OwnedSocket(NativeSocket socket) : socket_(socket) {}
  ~OwnedSocket() { close_native_socket(socket_); }
  OwnedSocket(const OwnedSocket&) = delete;
  OwnedSocket& operator=(const OwnedSocket&) = delete;
  OwnedSocket(OwnedSocket&& other) noexcept : socket_(other.release()) {}
  OwnedSocket& operator=(OwnedSocket&& other) noexcept {
    if (this != &other) {
      close_native_socket(socket_);
      socket_ = other.release();
    }
    return *this;
  }
  NativeSocket get() const noexcept { return socket_; }
  NativeSocket release() noexcept {
    const auto out = socket_;
    socket_ = kInvalidSocket;
    return out;
  }
  void close() noexcept {
    close_native_socket(socket_);
    socket_ = kInvalidSocket;
  }
  explicit operator bool() const noexcept { return socket_ != kInvalidSocket; }
 private:
  NativeSocket socket_ = kInvalidSocket;
};

struct SocketPair {
  OwnedSocket bridge;
  OwnedSocket ssh;
};

void set_nonblocking(NativeSocket socket) {
#ifdef _WIN32
  u_long mode = 1;
  if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
    throw std::runtime_error("failed to make embedded SSH bridge nonblocking");
  }
#else
  const int flags = fcntl(socket, F_GETFL, 0);
  if (flags < 0 || fcntl(socket, F_SETFL, flags | O_NONBLOCK) < 0) {
    throw std::runtime_error("failed to make embedded SSH bridge nonblocking");
  }
#endif
}

SocketPair make_socket_pair() {
#ifdef _WIN32
  ensure_winsock();
  OwnedSocket listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  if (!listener) throw std::runtime_error("socket failed for embedded SSH bridge");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
      listen(listener.get(), 1) != 0) {
    throw std::runtime_error("failed to create embedded SSH loopback bridge");
  }
  int length = static_cast<int>(sizeof(address));
  if (getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    throw std::runtime_error("getsockname failed for embedded SSH bridge");
  }
  OwnedSocket client(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  if (!client) throw std::runtime_error("socket failed for embedded SSH bridge client");
  if (connect(client.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
    throw std::runtime_error("connect failed for embedded SSH loopback bridge");
  }
  OwnedSocket server(accept(listener.get(), nullptr, nullptr));
  if (!server) throw std::runtime_error("accept failed for embedded SSH loopback bridge");
  set_nonblocking(client.get());
  return SocketPair{std::move(client), std::move(server)};
#else
  int pair[2] = {-1, -1};
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
    throw std::runtime_error(std::string("socketpair: ") + std::strerror(errno));
  }
  OwnedSocket bridge(pair[0]);
  OwnedSocket ssh(pair[1]);
  set_nonblocking(bridge.get());
  return SocketPair{std::move(bridge), std::move(ssh)};
#endif
}

void shutdown_socket_write(NativeSocket socket) noexcept {
#ifdef _WIN32
  (void)shutdown(socket, SD_SEND);
#else
  (void)shutdown(socket, SHUT_WR);
#endif
}

std::size_t socket_send_some(NativeSocket socket, std::span<const std::uint8_t> data) {
  if (data.empty()) return 0U;
#ifdef _WIN32
  const auto amount = static_cast<int>(std::min<std::size_t>(data.size(), 1U << 20U));
  const int n = send(socket, reinterpret_cast<const char*>(data.data()), amount, 0);
#else
  const auto amount = std::min<std::size_t>(data.size(), 1U << 20U);
#ifdef MSG_NOSIGNAL
  const auto n = send(socket, data.data(), amount, MSG_NOSIGNAL);
#else
  const auto n = send(socket, data.data(), amount, 0);
#endif
#endif
  if (n > 0) return static_cast<std::size_t>(n);
  if (n < 0 && socket_would_block()) return 0U;
  throw std::runtime_error("embedded SSH bridge send failed");
}

enum class SocketReadKind { data, would_block, eof };
struct SocketRead {
  SocketReadKind kind = SocketReadKind::would_block;
  std::vector<std::uint8_t> data;
};

SocketRead socket_read_some(NativeSocket socket) {
  std::array<std::uint8_t, 16U * 1024U> buffer{};
#ifdef _WIN32
  const int n = recv(socket, reinterpret_cast<char*>(buffer.data()),
                     static_cast<int>(buffer.size()), 0);
#else
  const auto n = recv(socket, buffer.data(), buffer.size(), 0);
#endif
  if (n > 0) {
    return SocketRead{SocketReadKind::data,
                      std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + n)};
  }
  if (n == 0) return SocketRead{SocketReadKind::eof, {}};
  if (socket_would_block()) return SocketRead{};
  throw std::runtime_error("embedded SSH bridge receive failed");
}

bool accepted_env(std::string_view key) {
  return key == "TERM" || key == "LANG" || key.rfind("LC_", 0) == 0;
}

class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess() { stop(); }
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  void start(const std::string& command,
             const std::vector<std::pair<std::string, std::string>>& environment) {
    if (started_) throw std::runtime_error("SSH session process already started");
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE child_stdin = nullptr;
    HANDLE child_stdout = nullptr;
    HANDLE child_stderr = nullptr;
    if (!CreatePipe(&child_stdin, &stdin_write_, &sa, 0) ||
        !CreatePipe(&stdout_read_, &child_stdout, &sa, 0) ||
        !CreatePipe(&stderr_read_, &child_stderr, &sa, 0)) {
      throw std::runtime_error("CreatePipe failed for embedded SSH shell");
    }
    SetHandleInformation(stdin_write_, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_read_, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderr_read_, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = child_stdin;
    si.hStdOutput = child_stdout;
    si.hStdError = child_stderr;
    PROCESS_INFORMATION pi{};
    std::string line = "powershell.exe -NoLogo";
    if (!command.empty()) {
      std::string escaped = command;
      std::size_t pos = 0U;
      while ((pos = escaped.find('"', pos)) != std::string::npos) {
        escaped.insert(pos, "`");
        pos += 2U;
      }
      line += " -Command \"" + escaped + "\"";
    }
    std::vector<char> mutable_line(line.begin(), line.end());
    mutable_line.push_back('\0');
    const BOOL ok = CreateProcessA(nullptr, mutable_line.data(), nullptr, nullptr, TRUE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(child_stdin);
    CloseHandle(child_stdout);
    CloseHandle(child_stderr);
    if (!ok) {
      close_handles();
      throw std::runtime_error("CreateProcess failed for embedded SSH shell");
    }
    process_ = pi.hProcess;
    CloseHandle(pi.hThread);
    (void)environment;
#else
    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
      throw std::runtime_error(std::string("pipe: ") + std::strerror(errno));
    }
    pid_ = fork();
    if (pid_ < 0) throw std::runtime_error(std::string("fork: ") + std::strerror(errno));
    if (pid_ == 0) {
      dup2(in_pipe[0], STDIN_FILENO);
      dup2(out_pipe[1], STDOUT_FILENO);
      dup2(err_pipe[1], STDERR_FILENO);
      close(in_pipe[0]); close(in_pipe[1]);
      close(out_pipe[0]); close(out_pipe[1]);
      close(err_pipe[0]); close(err_pipe[1]);
      for (const auto& [key, value] : environment) setenv(key.c_str(), value.c_str(), 1);
      const auto home = env_value("HOME");
      if (!home.empty()) (void)chdir(home.c_str());
      const auto configured_shell = env_value("SHELL");
      const std::string shell = configured_shell.empty() ? "/bin/sh" : configured_shell;
      if (command.empty()) {
        execl(shell.c_str(), shell.c_str(), "-l", static_cast<char*>(nullptr));
      } else {
        execl(shell.c_str(), shell.c_str(), "-c", command.c_str(), static_cast<char*>(nullptr));
      }
      _exit(127);
    }
    close(in_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[1]);
    stdin_fd_ = in_pipe[1];
    stdout_fd_ = out_pipe[0];
    stderr_fd_ = err_pipe[0];
    make_fd_nonblocking(stdin_fd_);
    make_fd_nonblocking(stdout_fd_);
    make_fd_nonblocking(stderr_fd_);
#endif
    started_ = true;
  }

  std::size_t write_stdin(std::span<const std::uint8_t> data) {
    if (!started_ || stdin_closed_ || data.empty()) return 0U;
#ifdef _WIN32
    DWORD written = 0;
    if (!WriteFile(stdin_write_, data.data(),
                   static_cast<DWORD>(std::min<std::size_t>(data.size(), 1U << 20U)),
                   &written, nullptr)) {
      close_stdin();
      return 0U;
    }
    return static_cast<std::size_t>(written);
#else
    const auto n = write(stdin_fd_, data.data(), data.size());
    if (n > 0) return static_cast<std::size_t>(n);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0U;
    close_stdin();
    return 0U;
#endif
  }

  void close_stdin() noexcept {
    if (stdin_closed_) return;
#ifdef _WIN32
    if (stdin_write_ != nullptr) CloseHandle(stdin_write_);
    stdin_write_ = nullptr;
#else
    if (stdin_fd_ >= 0) close(stdin_fd_);
    stdin_fd_ = -1;
#endif
    stdin_closed_ = true;
  }

  void pump_output(ssh_channel channel) {
    if (!started_ || channel == nullptr) return;
    drain_one(channel, false);
    drain_one(channel, true);
  }

  std::optional<int> poll_exit() {
    if (!started_ || exit_code_) return exit_code_;
#ifdef _WIN32
    if (WaitForSingleObject(process_, 0) != WAIT_OBJECT_0) return std::nullopt;
    DWORD code = 1;
    if (!GetExitCodeProcess(process_, &code)) code = 1;
    exit_code_ = static_cast<int>(code);
#else
    int status = 0;
    const auto result = waitpid(pid_, &status, WNOHANG);
    if (result == 0) return std::nullopt;
    if (result < 0) {
      exit_code_ = 1;
    } else if (WIFEXITED(status)) {
      exit_code_ = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      exit_code_ = 128 + WTERMSIG(status);
    } else {
      exit_code_ = 1;
    }
#endif
    return exit_code_;
  }

 private:
#ifndef _WIN32
  static void make_fd_nonblocking(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }
#endif

  void drain_one(ssh_channel channel, bool stderr_stream) {
    std::array<std::uint8_t, 16U * 1024U> buffer{};
    for (;;) {
#ifdef _WIN32
      HANDLE handle = stderr_stream ? stderr_read_ : stdout_read_;
      if (handle == nullptr) return;
      DWORD available = 0;
      if (!PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr) || available == 0) return;
      DWORD read_count = 0;
      const DWORD wanted = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
      if (!ReadFile(handle, buffer.data(), wanted, &read_count, nullptr) || read_count == 0) return;
      const int wrote = stderr_stream
                            ? ssh_channel_write_stderr(channel, buffer.data(), read_count)
                            : ssh_channel_write(channel, buffer.data(), read_count);
#else
      const int fd = stderr_stream ? stderr_fd_ : stdout_fd_;
      if (fd < 0) return;
      const auto read_count = read(fd, buffer.data(), buffer.size());
      if (read_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
      if (read_count <= 0) return;
      const int wrote = stderr_stream
                            ? ssh_channel_write_stderr(channel, buffer.data(), static_cast<uint32_t>(read_count))
                            : ssh_channel_write(channel, buffer.data(), static_cast<uint32_t>(read_count));
#endif
      if (wrote == SSH_ERROR) return;
    }
  }

  void stop() noexcept {
    close_stdin();
#ifdef _WIN32
    if (process_ != nullptr) {
      if (!exit_code_) TerminateProcess(process_, 1);
      CloseHandle(process_);
      process_ = nullptr;
    }
    close_handles();
#else
    if (pid_ > 0 && !exit_code_) {
      kill(pid_, SIGTERM);
      int status = 0;
      (void)waitpid(pid_, &status, 0);
    }
    if (stdout_fd_ >= 0) close(stdout_fd_);
    if (stderr_fd_ >= 0) close(stderr_fd_);
    stdout_fd_ = stderr_fd_ = -1;
#endif
  }

#ifdef _WIN32
  void close_handles() noexcept {
    if (stdin_write_ != nullptr) CloseHandle(stdin_write_);
    if (stdout_read_ != nullptr) CloseHandle(stdout_read_);
    if (stderr_read_ != nullptr) CloseHandle(stderr_read_);
    stdin_write_ = stdout_read_ = stderr_read_ = nullptr;
  }
  HANDLE process_ = nullptr;
  HANDLE stdin_write_ = nullptr;
  HANDLE stdout_read_ = nullptr;
  HANDLE stderr_read_ = nullptr;
#else
  pid_t pid_ = -1;
  int stdin_fd_ = -1;
  int stdout_fd_ = -1;
  int stderr_fd_ = -1;
#endif
  bool started_ = false;
  bool stdin_closed_ = false;
  std::optional<int> exit_code_;
};

struct SessionContext {
  ssh_channel channel = nullptr;
  ssh_channel_callbacks_struct channel_callbacks{};
  std::unique_ptr<ChildProcess> process;
  std::vector<std::pair<std::string, std::string>> environment;
  bool pty_requested = false;
  int pty_width = 80;
  int pty_height = 24;
  std::string error;
};

int auth_none(ssh_session, const char*, void*) { return SSH_AUTH_SUCCESS; }

int channel_data(ssh_session, ssh_channel, void* data, uint32_t len, int is_stderr,
                 void* userdata) {
  auto* context = static_cast<SessionContext*>(userdata);
  if (context == nullptr || is_stderr != 0 || !context->process) return 0;
  try {
    return static_cast<int>(context->process->write_stdin(
        std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(data), len)));
  } catch (const std::exception& e) {
    context->error = e.what();
    return 0;
  }
}

void channel_eof(ssh_session, ssh_channel, void* userdata) {
  auto* context = static_cast<SessionContext*>(userdata);
  if (context != nullptr && context->process) context->process->close_stdin();
}

int channel_env(ssh_session, ssh_channel, const char* name, const char* value,
                void* userdata) {
  auto* context = static_cast<SessionContext*>(userdata);
  if (context == nullptr || name == nullptr || value == nullptr ||
      !accepted_env(name) || context->process) {
    return SSH_ERROR;
  }
  context->environment.emplace_back(name, value);
  return SSH_OK;
}

int channel_pty(ssh_session, ssh_channel, const char* term, int width, int height,
                int, int, void* userdata) {
  auto* context = static_cast<SessionContext*>(userdata);
  if (context == nullptr) return SSH_ERROR;
  context->pty_requested = true;
  context->pty_width = width > 0 ? width : 80;
  context->pty_height = height > 0 ? height : 24;
  if (term != nullptr && *term != '\0') context->environment.emplace_back("TERM", term);
  // The first embedded-server slice accepts the request so ordinary OpenSSH
  // remains usable; the process backend is upgraded to a real PTY/ConPTY in
  // the next parity layer.
  return SSH_OK;
}

int channel_window(ssh_session, ssh_channel, int width, int height, int, int,
                   void* userdata) {
  auto* context = static_cast<SessionContext*>(userdata);
  if (context == nullptr) return SSH_ERROR;
  context->pty_width = width > 0 ? width : context->pty_width;
  context->pty_height = height > 0 ? height : context->pty_height;
  return SSH_OK;
}

int start_session_process(SessionContext* context, const char* command) {
  if (context == nullptr || context->process) return SSH_ERROR;
  try {
    context->process = std::make_unique<ChildProcess>();
    context->process->start(command == nullptr ? std::string{} : std::string(command),
                            context->environment);
    if (context->pty_requested && (command == nullptr || *command == '\0')) {
      static constexpr std::string_view motd = "🐈 Connected via tailcat SSH.\r\n";
      (void)ssh_channel_write(context->channel, motd.data(),
                              static_cast<uint32_t>(motd.size()));
    }
    return SSH_OK;
  } catch (const std::exception& e) {
    context->error = e.what();
    context->process.reset();
    return SSH_ERROR;
  }
}

int channel_shell(ssh_session, ssh_channel, void* userdata) {
  return start_session_process(static_cast<SessionContext*>(userdata), nullptr);
}

int channel_exec(ssh_session, ssh_channel, const char* command, void* userdata) {
  return start_session_process(static_cast<SessionContext*>(userdata), command);
}

int channel_subsystem(ssh_session, ssh_channel, const char*, void*) {
  return SSH_ERROR;
}

ssh_channel channel_open(ssh_session session, void* userdata) {
  auto* context = static_cast<SessionContext*>(userdata);
  if (context == nullptr || context->channel != nullptr) return nullptr;
  context->channel = ssh_channel_new(session);
  if (context->channel == nullptr) return nullptr;
  ssh_callbacks_init(&context->channel_callbacks);
  if (ssh_set_channel_callbacks(context->channel, &context->channel_callbacks) != SSH_OK) {
    ssh_channel_free(context->channel);
    context->channel = nullptr;
    return nullptr;
  }
  return context->channel;
}

struct WorkerState {
  std::atomic<bool> done{false};
  std::mutex mutex;
  std::string error;
};

void run_ssh_session(NativeSocket fd, const std::string& host_key,
                     const std::shared_ptr<WorkerState>& state) noexcept {
  bool fd_owned_by_libssh = false;
  ssh_bind binding = nullptr;
  ssh_session session = nullptr;
  ssh_event event = nullptr;
  SessionContext context;
  try {
    binding = ssh_bind_new();
    session = ssh_new();
    if (binding == nullptr || session == nullptr) {
      throw std::runtime_error("failed to allocate embedded SSH server session");
    }
    bool process_config = false;
    if (ssh_bind_options_set(binding, SSH_BIND_OPTIONS_HOSTKEY, host_key.c_str()) != SSH_OK ||
        ssh_bind_options_set(binding, SSH_BIND_OPTIONS_PROCESS_CONFIG, &process_config) != SSH_OK) {
      throw std::runtime_error(std::string("failed to configure embedded SSH server: ") +
                               ssh_get_error(binding));
    }

    context.channel_callbacks.userdata = &context;
    context.channel_callbacks.channel_data_function = channel_data;
    context.channel_callbacks.channel_eof_function = channel_eof;
    context.channel_callbacks.channel_pty_request_function = channel_pty;
    context.channel_callbacks.channel_shell_request_function = channel_shell;
    context.channel_callbacks.channel_pty_window_change_function = channel_window;
    context.channel_callbacks.channel_exec_request_function = channel_exec;
    context.channel_callbacks.channel_env_request_function = channel_env;
    context.channel_callbacks.channel_subsystem_request_function = channel_subsystem;

    ssh_server_callbacks_struct callbacks{};
    callbacks.userdata = &context;
    callbacks.auth_none_function = auth_none;
    callbacks.channel_open_request_session_function = channel_open;
    ssh_callbacks_init(&callbacks);
    if (ssh_set_server_callbacks(session, &callbacks) != SSH_OK) {
      throw std::runtime_error("failed to install embedded SSH server callbacks");
    }
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_NONE);
    long timeout_seconds = 10;
    (void)ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout_seconds);

    if (ssh_bind_accept_fd(binding, session, static_cast<socket_t>(fd)) != SSH_OK) {
      throw std::runtime_error(std::string("embedded SSH accept failed: ") + ssh_get_error(binding));
    }
    fd_owned_by_libssh = true;
    if (ssh_handle_key_exchange(session) != SSH_OK) {
      throw std::runtime_error(std::string("embedded SSH key exchange failed: ") + ssh_get_error(session));
    }
    event = ssh_event_new();
    if (event == nullptr || ssh_event_add_session(event, session) != SSH_OK) {
      throw std::runtime_error("failed to create embedded SSH event loop");
    }

    while (ssh_is_connected(session)) {
      if (ssh_event_dopoll(event, 20) == SSH_ERROR) break;
      if (context.process && context.channel != nullptr) {
        context.process->pump_output(context.channel);
        if (const auto code = context.process->poll_exit()) {
          // Drain any bytes written just before process exit before closing the
          // SSH channel, matching upstream's output-before-Wait ordering.
          for (int i = 0; i < 5; ++i) {
            context.process->pump_output(context.channel);
            std::this_thread::sleep_for(2ms);
          }
          (void)ssh_channel_request_send_exit_status(context.channel, *code);
          (void)ssh_channel_send_eof(context.channel);
          (void)ssh_channel_close(context.channel);
          break;
        }
      }
      if (context.channel != nullptr && ssh_channel_is_closed(context.channel)) break;
      if (!context.error.empty()) throw std::runtime_error(context.error);
    }
  } catch (const std::exception& e) {
    std::lock_guard<std::mutex> lock(state->mutex);
    state->error = e.what();
  }

  context.process.reset();
  if (context.channel != nullptr) {
    ssh_channel_free(context.channel);
    context.channel = nullptr;
  }
  if (event != nullptr) ssh_event_free(event);
  if (session != nullptr) {
    ssh_disconnect(session);
    ssh_free(session);  // closes fd after ssh_bind_accept_fd succeeded
  }
  if (binding != nullptr) ssh_bind_free(binding);
  if (!fd_owned_by_libssh) close_native_socket(fd);
  state->done.store(true, std::memory_order_release);
}

}  // namespace

struct EmbeddedSshServer::Impl {
  struct Connection {
    std::shared_ptr<LwipTcpStream> tunnel;
    OwnedSocket bridge;
    std::shared_ptr<WorkerState> worker;
    std::thread thread;
    std::vector<std::uint8_t> pending_to_ssh;
    std::size_t pending_to_ssh_offset = 0U;
    std::vector<std::uint8_t> pending_to_tunnel;
    std::size_t pending_to_tunnel_offset = 0U;
    bool bridge_write_shutdown = false;
    bool bridge_eof = false;
    bool tunnel_write_shutdown = false;
    bool finished = false;
    bool error_reported = false;
  };

  TailcatServerDataPlane& data;
  std::shared_ptr<LwipTcpListener> listener;
  std::string host_key;
  bool verbose = false;
  std::vector<Connection> connections;

  Impl(TailcatServerDataPlane& data_plane, bool log_verbose)
      : data(data_plane), listener(data.listen(22U)),
        host_key(ensure_ssh_host_key()), verbose(log_verbose) {}

  ~Impl() {
    listener->close();
    for (auto& connection : connections) {
      connection.bridge.close();
      if (connection.thread.joinable()) connection.thread.join();
    }
  }

  void accept_new() {
    for (;;) {
      auto tunnel = listener->accept();
      if (!tunnel) return;
      try {
        auto pair = make_socket_pair();
        auto worker = std::make_shared<WorkerState>();
        const auto key = host_key;
        NativeSocket ssh_fd = pair.ssh.release();
        std::thread thread([ssh_fd, key, worker] { run_ssh_session(ssh_fd, key, worker); });
        connections.push_back(Connection{std::move(tunnel), std::move(pair.bridge),
                                         std::move(worker), std::move(thread)});
      } catch (...) {
        tunnel->close();
        throw;
      }
    }
  }

  void service(Connection& connection) {
    if (connection.finished) return;
    try {
      if (connection.tunnel->failed()) {
        connection.bridge.close();
        connection.finished = true;
        return;
      }

      if (connection.pending_to_ssh_offset == connection.pending_to_ssh.size()) {
        connection.pending_to_ssh = connection.tunnel->read_available();
        connection.pending_to_ssh_offset = 0U;
      }
      if (connection.pending_to_ssh_offset < connection.pending_to_ssh.size()) {
        const std::span<const std::uint8_t> remaining(
            connection.pending_to_ssh.data() + connection.pending_to_ssh_offset,
            connection.pending_to_ssh.size() - connection.pending_to_ssh_offset);
        connection.pending_to_ssh_offset += socket_send_some(connection.bridge.get(), remaining);
      }
      if (connection.tunnel->eof() && !connection.bridge_write_shutdown) {
        shutdown_socket_write(connection.bridge.get());
        connection.bridge_write_shutdown = true;
      }

      if (connection.pending_to_tunnel_offset == connection.pending_to_tunnel.size() &&
          !connection.bridge_eof) {
        const auto read = socket_read_some(connection.bridge.get());
        if (read.kind == SocketReadKind::data) {
          connection.pending_to_tunnel = read.data;
          connection.pending_to_tunnel_offset = 0U;
        } else if (read.kind == SocketReadKind::eof) {
          connection.bridge_eof = true;
          if (!connection.tunnel_write_shutdown) {
            connection.tunnel->shutdown_write();
            connection.tunnel_write_shutdown = true;
          }
        }
      }
      if (connection.pending_to_tunnel_offset < connection.pending_to_tunnel.size()) {
        const std::span<const std::uint8_t> remaining(
            connection.pending_to_tunnel.data() + connection.pending_to_tunnel_offset,
            connection.pending_to_tunnel.size() - connection.pending_to_tunnel_offset);
        connection.pending_to_tunnel_offset += connection.tunnel->write(remaining);
      }

      if (connection.worker->done.load(std::memory_order_acquire)) {
        std::string worker_error;
        {
          std::lock_guard<std::mutex> lock(connection.worker->mutex);
          worker_error = connection.worker->error;
        }
        if (verbose && !worker_error.empty() && !connection.error_reported) {
          std::cerr << "# embedded SSH session: " << worker_error << '\n';
          connection.error_reported = true;
        }
        if (connection.pending_to_tunnel_offset == connection.pending_to_tunnel.size()) {
          connection.bridge.close();
          connection.tunnel->close();
          if (connection.thread.joinable()) connection.thread.join();
          connection.finished = true;
        }
      }
    } catch (const std::exception& e) {
      if (verbose) std::cerr << "# embedded SSH bridge: " << e.what() << '\n';
      connection.bridge.close();
      connection.tunnel->close();
      if (connection.worker->done.load(std::memory_order_acquire) && connection.thread.joinable()) {
        connection.thread.join();
      }
      connection.finished = true;
    }
  }

  void poll() {
    accept_new();
    for (auto& connection : connections) service(connection);
    connections.erase(
        std::remove_if(connections.begin(), connections.end(),
                       [](const Connection& connection) { return connection.finished; }),
        connections.end());
  }
};

EmbeddedSshServer::EmbeddedSshServer(TailcatServerDataPlane& data_plane, bool verbose)
    : impl_(std::make_unique<Impl>(data_plane, verbose)) {}
EmbeddedSshServer::~EmbeddedSshServer() = default;
void EmbeddedSshServer::poll() { impl_->poll(); }

}  // namespace tailcat
