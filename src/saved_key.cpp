// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/saved_key.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
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
namespace fs = std::filesystem;

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

bool explicit_path(std::string_view value) {
  return value.find('/') != std::string_view::npos ||
         value.find('\\') != std::string_view::npos;
}

}  // namespace

SavedTailcatKey new_saved_tailcat_key(bool use_psk, std::int64_t region_id) {
  SavedTailcatKey out;
  out.identity = generate_node_key();
  if (use_psk) out.preshared_key = generate_secret_key();
  out.region_id = region_id;
  return out;
}

std::string tailcat_keys_dir() {
  return (user_config_root() / "tailcat" / "keys").string();
}

std::string resolve_tailcat_key_path(const std::string& name_or_path) {
  if (name_or_path.empty()) throw std::invalid_argument("Tailcat key name is empty");
  if (explicit_path(name_or_path)) return name_or_path;
  if (name_or_path == "." || name_or_path == "..") {
    throw std::invalid_argument("invalid Tailcat key name");
  }
  return (fs::path(tailcat_keys_dir()) / (name_or_path + ".private.json")).string();
}

bool saved_tailcat_key_exists(const std::string& name_or_path) {
  return fs::exists(resolve_tailcat_key_path(name_or_path));
}

std::vector<std::string> list_saved_tailcat_keys() {
  std::vector<std::string> names;
  const fs::path dir(tailcat_keys_dir());
  std::error_code ec;
  if (!fs::exists(dir, ec)) return names;
  if (ec) throw std::runtime_error("failed to inspect Tailcat key directory: " + ec.message());
  for (const auto& entry : fs::directory_iterator(dir)) {
    if (!entry.is_regular_file()) continue;
    const auto filename = entry.path().filename().string();
    constexpr std::string_view suffix = ".private.json";
    if (filename.size() <= suffix.size() ||
        filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) != 0) {
      continue;
    }
    names.push_back(filename.substr(0, filename.size() - suffix.size()));
  }
  std::sort(names.begin(), names.end());
  return names;
}

void delete_saved_tailcat_key(const std::string& name_or_path) {
  const auto path = resolve_tailcat_key_path(name_or_path);
  std::error_code ec;
  const bool removed = fs::remove(path, ec);
  if (ec) throw std::runtime_error("failed to delete Tailcat key: " + ec.message());
  if (!removed) throw std::runtime_error("Tailcat key does not exist: " + path);
}

std::string node_public_text(const Key32& key) {
  return hex_key("nodekey:", key);
}

SavedTailcatKey load_saved_tailcat_key(const std::string& path_or_name) {
  const auto path = resolve_tailcat_key_path(path_or_name);
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

void save_tailcat_key(const std::string& path_or_name, const SavedTailcatKey& key) {
  const auto path = resolve_tailcat_key_path(path_or_name);
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

  const auto parent = fs::path(path).parent_path();
  if (!parent.empty()) {
    std::error_code ec;
    fs::create_directories(parent, ec);
    if (ec) throw std::runtime_error("failed to create Tailcat key directory: " + ec.message());
  }

  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) throw std::runtime_error("failed to create Tailcat key file: " + path);
  output << value.dump(2) << '\n';
  output.close();
  if (!output) throw std::runtime_error("failed to write Tailcat key file: " + path);
  make_private(path);
}

}  // namespace tailcat
