// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/cli.hpp"
#include "tailcat/crypto.hpp"
#include "tailcat/data_plane.hpp"
#include "tailcat/derp_http.hpp"
#include "tailcat/derp_map.hpp"
#include "tailcat/extra_commands.hpp"
#include "tailcat/forward_command.hpp"
#include "tailcat/platform.hpp"
#include "tailcat/port_forward.hpp"
#include "tailcat/protocol.hpp"
#include "tailcat/rendezvous.hpp"
#include "tailcat/ssh_command.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#ifndef TAILCAT_VERSION
#define TAILCAT_VERSION "0.1.0"
#endif

namespace tailcat {
namespace {

using namespace std::chrono_literals;
constexpr std::string_view kVersion = TAILCAT_VERSION;
constexpr std::string_view kDefaultDerpMap = "https://tailcat.dev/derpmap.json";

bool is_help(std::string_view arg) { return arg == "-h" || arg == "--help"; }
bool is_version(std::string_view arg) {
  return arg == "-V" || arg == "--version" || arg == "version";
}

int unavailable(std::string_view command) {
  std::cerr << "tailcat: '" << command
            << "' is not enabled in this native build yet.\n";
  return 2;
}

std::string key_hex(const Key32& key) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const auto b : key) out << std::setw(2) << static_cast<unsigned>(b);
  return out.str();
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
  return region_by_id(fetch_derp_map(std::string(kDefaultDerpMap)),
                      info.region_id);
}

std::uint16_t parse_port(std::string_view text) {
  if (text.empty()) throw std::invalid_argument("empty port number");
  std::size_t consumed = 0;
  const auto value = std::stoul(std::string(text), &consumed, 10);
  if (consumed != text.size() || value == 0 || value > 65535U) {
    throw std::invalid_argument("invalid TCP port: " + std::string(text));
  }
  return static_cast<std::uint16_t>(value);
}

int run_parse(const std::vector<std::string>& args) {
  if (args.size() != 1U) {
    throw std::invalid_argument("parse requires one <tc-address>");
  }
  const auto info = parse_tailcat_addr(args[0]);
  std::cout << "serverPublic=" << key_hex(info.server_public) << '\n';
  if (info.server_disco_public) {
    std::cout << "serverDiscoPublic=" << key_hex(*info.server_disco_public)
              << '\n';
  }
  std::cout << "presharedKey=" << (info.preshared_key ? "present" : "absent")
            << '\n';
  std::cout << "regionID=" << info.region_id << '\n';
  std::cout << "embeddedRegions=" << info.regions.size() << '\n';
  return 0;
}

struct InputState {
  std::mutex mutex;
  std::deque<std::vector<std::uint8_t>> chunks;
  bool done = false;
};

std::shared_ptr<InputState> start_stdin_reader() {
  auto state = std::make_shared<InputState>();
  std::thread([state] {
    std::array<char, 16 * 1024> buffer{};
    for (;;) {
      std::cin.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
      const auto count = std::cin.gcount();
      if (count > 0) {
        std::vector<std::uint8_t> chunk(static_cast<std::size_t>(count));
        for (std::streamsize i = 0; i < count; ++i) {
          chunk[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(
              static_cast<unsigned char>(buffer[static_cast<std::size_t>(i)]));
        }
        std::lock_guard<std::mutex> lock(state->mutex);
        state->chunks.push_back(std::move(chunk));
      }
      if (count == 0 || std::cin.eof() || std::cin.bad()) break;
    }
    std::lock_guard<std::mutex> lock(state->mutex);
    state->done = true;
  }).detach();
  return state;
}

int run_client(std::string_view address, const std::vector<std::string>& args,
               bool verbose) {
  if (args.size() > 1U) {
    throw std::invalid_argument(
        "connect accepts at most one TCP port argument");
  }
  const auto port =
      args.empty() ? static_cast<std::uint16_t>(1U) : parse_port(args[0]);
  auto info = parse_tailcat_addr(address);
  const auto region = resolve_region(info);
  const auto node = primary_derp_node(region);
  const auto identity = generate_node_key();

  if (verbose) {
    std::cerr << "# connecting through DERP region " << region.region_id
              << " (" << region.region_code << ")\n";
  }

  DerpHttpClient derp(node, identity, "tailcat");
  derp.connect();
  TailcatClientDataPlane data(derp, identity, std::move(info));
  data.connect(15s);
  auto stream = data.dial(port);

  const auto connect_deadline = std::chrono::steady_clock::now() + 15s;
  while (!stream->connected()) {
    if (stream->failed()) {
      throw std::runtime_error("TCP connect failed: " + stream->error());
    }
    if (std::chrono::steady_clock::now() >= connect_deadline) {
      throw std::runtime_error("timed out establishing Tailcat TCP stream");
    }
    (void)data.pump_for(20ms);
  }

  const auto input = start_stdin_reader();
  std::vector<std::uint8_t> pending;
  std::size_t pending_offset = 0U;
  bool write_shutdown = false;

  for (;;) {
    (void)data.pump_for(20ms);
    if (stream->failed()) {
      throw std::runtime_error("Tailcat TCP stream failed: " + stream->error());
    }

    const auto received = stream->read_available();
    if (!received.empty()) {
      std::cout.write(reinterpret_cast<const char*>(received.data()),
                      static_cast<std::streamsize>(received.size()));
      std::cout.flush();
    }

    if (pending_offset == pending.size()) {
      pending.clear();
      pending_offset = 0U;
      std::lock_guard<std::mutex> lock(input->mutex);
      if (!input->chunks.empty()) {
        pending = std::move(input->chunks.front());
        input->chunks.pop_front();
      } else if (input->done && !write_shutdown) {
        stream->shutdown_write();
        write_shutdown = true;
      }
    }

    if (pending_offset < pending.size()) {
      const std::span<const std::uint8_t> remaining(
          pending.data() + pending_offset, pending.size() - pending_offset);
      pending_offset += stream->write(remaining);
    }

    if (stream->eof()) {
      stream->close();
      const auto drain_deadline = std::chrono::steady_clock::now() + 250ms;
      while (std::chrono::steady_clock::now() < drain_deadline) {
        (void)data.pump_for(10ms);
      }
      return 0;
    }
  }
}

int run_ping(const std::vector<std::string>& args, bool verbose) {
  if (args.size() != 1U) {
    throw std::invalid_argument("ping requires one <tc-address>");
  }
  const auto info = parse_tailcat_addr(args[0]);
  const auto region = resolve_region(info);
  const auto node = primary_derp_node(region);
  const auto identity = generate_node_key();
  const auto disco = derive_disco_key(identity.private_key);
  DerpHttpClient derp(node, identity, "tailcat");
  derp.connect();
  const auto latency = rendezvous_client(derp, identity, disco.public_key,
                                         info.server_public, 10s);
  std::cout << "pong in " << latency.count() << "ms via DERP(";
  if (!region.region_code.empty()) {
    std::cout << region.region_code;
  } else {
    std::cout << region.region_id;
  }
  std::cout << ")\n";
  if (verbose) std::cerr << "# DERP relay " << node.host_name << '\n';
  return 0;
}

struct ServerBootstrap {
  NodeKeyPair identity;
  NodeKeyPair disco;
  std::optional<Key32> psk;
  DerpRegion region;
  DerpNode node;
  ConnInfo info;
  std::string address;
};

ServerBootstrap make_server_bootstrap(bool use_psk) {
  ServerBootstrap out;
  out.identity = generate_node_key();
  out.disco = derive_disco_key(out.identity.private_key);
  if (use_psk) out.psk = generate_secret_key();
  const auto map = fetch_derp_map(std::string(kDefaultDerpMap));
  out.region = select_derp_region(map);
  out.node = primary_derp_node(out.region);
  out.info.server_public = out.identity.public_key;
  out.info.server_disco_public = out.disco.public_key;
  out.info.preshared_key = out.psk;
  out.info.region_id = out.region.region_id;
  out.address = encode_tailcat_addr(out.info);
  return out;
}

void log_server_address(const ServerBootstrap& server, bool verbose) {
  std::cerr << "# Selected bootstrap relay region " << server.region.region_id;
  if (!server.region.region_name.empty()) {
    std::cerr << ", " << server.region.region_name;
  }
  std::cerr << '\n';
  std::cerr << "# 🐈 Server listening with new address: " << server.address
            << '\n';
  if (verbose) std::cerr << "# DERP relay " << server.node.host_name << '\n';
  if (!server.psk) {
    std::cerr << "# ⚠️ WARNING: serving without a WireGuard PSK\n";
  }
}

int run_default_server(bool verbose) {
  auto server = make_server_bootstrap(true);
  DerpHttpClient derp(server.node, server.identity, "tailcat");
  derp.connect();
  TailcatServerDataPlane data(derp, server.identity, server.psk);
  auto listener = data.listen(1U);
  log_server_address(server, verbose);

  std::shared_ptr<LwipTcpStream> stream;
  for (;;) {
    (void)data.pump_for(20ms);
    if (!stream) stream = listener->accept();
    if (!stream) continue;
    if (stream->failed()) {
      throw std::runtime_error("Tailcat TCP stream failed: " + stream->error());
    }

    const auto received = stream->read_available();
    if (!received.empty()) {
      std::cout.write(reinterpret_cast<const char*>(received.data()),
                      static_cast<std::streamsize>(received.size()));
      std::cout.flush();
    }
    if (stream->eof()) {
      stream->close();
      listener->close();
      return 0;
    }
  }
}

int run_serve(const std::vector<std::string>& args, bool verbose) {
  bool use_psk = true;
  std::vector<std::uint16_t> ports;
  for (const auto& arg : args) {
    if (arg == "--psk=false") {
      use_psk = false;
    } else if (arg == "--psk=true") {
      use_psk = true;
    } else if (arg == "ssh") {
      ports.push_back(22U);
    } else if (!arg.empty() && arg[0] == '-') {
      throw std::invalid_argument("unsupported serve option: " + arg);
    } else {
      ports.push_back(parse_port(arg));
    }
  }
  if (ports.empty()) {
    throw std::invalid_argument("serve requires ssh or one or more TCP ports");
  }

  auto server = make_server_bootstrap(use_psk);
  DerpHttpClient derp(server.node, server.identity, "tailcat");
  derp.connect();
  TailcatServerDataPlane data(derp, server.identity, server.psk);
  ServedTcpPorts forwarding(data, std::move(ports));
  log_server_address(server, verbose);
  if (verbose) {
    for (const auto port : forwarding.ports()) {
      if (port == 22U) {
        std::cerr << "# serving SSH -> 127.0.0.1:22\n";
      } else {
        std::cerr << "# serving TCP " << port << " -> 127.0.0.1:" << port
                  << '\n';
      }
    }
  }

  for (;;) {
    (void)data.pump_for(10ms);
    forwarding.poll();
  }
}

}  // namespace

CommandLine parse_command_line(int argc, char** argv) {
  CommandLine out;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (out.command.empty()) {
      if (is_help(arg)) {
        out.show_help = true;
        continue;
      }
      if (is_version(arg)) {
        out.show_version = true;
        continue;
      }
      if (arg == "-v" || arg == "--verbose") {
        out.verbose = true;
        continue;
      }
      if (!arg.empty() && arg[0] != '-') {
        out.command = arg;
        continue;
      }
    }
    out.args.push_back(arg);
  }
  return out;
}

std::string usage() {
  std::ostringstream out;
  out << "tailcat " << kVersion << " (native C++20)\n\n"
      << "Usage:\n"
      << "  tailcat [options]                         Listen for a pipe connection\n"
      << "  tailcat <tc-address> [port]               Connect to a peer\n"
      << "  tailcat serve [--psk=false] (ssh|PORT)...\n"
      << "                                             Proxy selected services to localhost\n"
      << "  tailcat ssh [-p PORT] [user@]<tc-address> [command ...]\n"
      << "                                             Run system OpenSSH through Tailcat\n"
      << "  tailcat cp [scp options] SOURCE DEST      Copy with system scp through Tailcat\n"
      << "  tailcat forward [--bind=ADDR] TCADDR [LOCAL:]REMOTE...\n"
      << "                                             Forward local TCP through Tailcat\n"
      << "  tailcat browse ...                        Open a forwarded HTTP service\n"
      << "  tailcat recv ...                          Receive files\n"
      << "  tailcat socks ...                         Run a SOCKS proxy\n"
      << "  tailcat ping <tc-address>                 Probe a peer over DERP\n"
      << "  tailcat genkey ...                        Generate reusable connection material\n"
      << "  tailcat parse <tc-address>                Decode a tailcat address\n\n"
      << "Options:\n"
      << "  -h, --help       Show this help\n"
      << "  -V, --version    Show version\n"
      << "  -v, --verbose    Enable diagnostic logging\n";
  return out.str();
}

int run(const CommandLine& cli) {
  initialize_crypto();
  if (cli.show_version) {
    std::cout << "tailcat " << kVersion << " (" << platform_name() << ")\n";
    return 0;
  }
  if (cli.show_help) {
    std::cout << usage();
    return 0;
  }

  if (cli.command.empty()) return run_default_server(cli.verbose);
  if (cli.command == "parse") return run_parse(cli.args);
  if (cli.command == "ping") return run_ping(cli.args, cli.verbose);
  if (cli.command == "serve") return run_serve(cli.args, cli.verbose);
  if (cli.command == "forward") {
    return run_forward_command(cli.args, cli.verbose);
  }
  if (cli.command == "ssh") return run_ssh_command(cli.args, cli.verbose);
  if (cli.command.rfind("tc", 0) == 0) {
    return run_client(cli.command, cli.args, cli.verbose);
  }
  if (const auto extra = run_extra_command(cli.command, cli.args, cli.verbose)) {
    return *extra;
  }

  static const std::unordered_set<std::string> commands = {
      "browse", "recv", "socks", "genkey", "ls"};
  if (commands.contains(cli.command)) return unavailable(cli.command);

  std::cerr << "tailcat: unknown command or address: " << cli.command << "\n\n"
            << usage();
  return 2;
}

}  // namespace tailcat
