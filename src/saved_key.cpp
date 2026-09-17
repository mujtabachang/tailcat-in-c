// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/saved_key.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <io.h>
#include <sys/stat.h>
#else
#include <sys/stat.h>
#endif

namespace tailcat {
namespace {

using nlohmann::json;

std::string hex_key(std::string_view prefix, const Key32& key) {
  std::ostringstream out;
  out << prefix << std::hex << std::setfill('0');
  for (const auto byte : key) out << std::setw(2) << static_cast<unsigned>(byte);
  return out.str();
}

unsigned hex_nibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
  c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (c >= 'a' && c <= 'f') return 10U + static_cast<unsigned>(c - 'a');
  throw std::invalid_argument("invalid hexadecimal key text");
}

Key32 parse_key(std::string_view text, std::string_view prefix) {
  if (!text.starts_with(prefix)) {
    throw std::invalid_argument("key has wrong type prefix");
  }
  text.remove_prefix(prefix.size());
  if (text.size() != 64U) throw std::invalid_argument("key has wrong length");
  Key32 out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>((hex_nibble(text[i * 2U]) << 4U) |
                                       hex_nibble(text[i * 2U + 1U]));
  }
  return out;
}

void make_private(const std::string& path) {
#ifdef _WIN32
  if (_chmod(path.c_str(), _S_IREAD | _S_IWRITE) != 0) {
    throw std::runtime_error("failed to set private key permissions on " + path);
  }
#else
  if (chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
    throw std::runtime_error("failed to set private key permissions on " + path);
  }
#endif
}

}  // namespace

SavedTailcatKey new_saved_tailcat_key(bool use_psk, std::int64_t region_id) {
  SavedTailcatKey out;
  out.identity = generate_node_key();
  if (use_psk) out.preshared_key = generate_secret_key();
  out.region_id = region_id;
  return out;
}

SavedTailcatKey load_saved_tailcat_key(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("failed to open Tailcat key file: " + path);
  json value;
  input >> value;

  SavedTailcatKey out;
  const auto private_text = value.at("Private").get<std::string>();
  out.identity.private_key = parse_key(private_text, "privkey:");
  out.identity.public_key = node_public_from_private(out.identity.private_key);

  const auto& public_value = value.at("Public");
  if (public_value.contains("ServerPublic")) {
    const auto public_key =
        parse_key(public_value.at("ServerPublic").get<std::string>(), "nodekey:");
    if (public_key != out.identity.public_key) {
      throw std::runtime_error("saved Tailcat public key does not match private key");
    }
  }
  if (public_value.contains("ServerDiscoPublic")) {
    const auto saved_disco = parse_key(
        public_value.at("ServerDiscoPublic").get<std::string>(), "discokey:");
    const auto derived = derive_disco_key(out.identity.private_key).public_key;
    if (saved_disco != derived) {
      throw std::runtime_error("saved Tailcat disco key does not match private key");
    }
  }
  if (public_value.contains("PresharedKey")) {
    out.preshared_key =
        parse_key(public_value.at("PresharedKey").get<std::string>(), "psk:");
  }
  if (public_value.contains("RegionID")) {
    out.region_id = public_value.at("RegionID").get<std::int64_t>();
  }
  return out;
}

void save_tailcat_key(const std::string& path, const SavedTailcatKey& key) {
  if (path.empty()) throw std::invalid_argument("Tailcat key path is empty");
  const auto disco = derive_disco_key(key.identity.private_key);
  json public_value = {
      {"ServerPublic", hex_key("nodekey:", key.identity.public_key)},
      {"ServerDiscoPublic", hex_key("discokey:", disco.public_key)},
  };
  if (key.preshared_key) {
    public_value["PresharedKey"] = hex_key("psk:", *key.preshared_key);
  }
  if (key.region_id != 0) public_value["RegionID"] = key.region_id;

  const json value = {
      {"Private", hex_key("privkey:", key.identity.private_key)},
      {"Public", std::move(public_value)},
  };

  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) throw std::runtime_error("failed to create Tailcat key file: " + path);
  output << value.dump(2) << '\n';
  output.close();
  if (!output) throw std::runtime_error("failed to write Tailcat key file: " + path);
  make_private(path);
}

}  // namespace tailcat
