// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/ssh_authorized_keys.hpp"

#include <curl/curl.h>
#include <libssh/libssh.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace tailcat {
namespace {

namespace fs = std::filesystem;

std::string trim(std::string_view value) {
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
    value.remove_prefix(1U);
  }
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
    value.remove_suffix(1U);
  }
  return std::string(value);
}

void ensure_curl() {
  static std::once_flag once;
  std::call_once(once, [] {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
      throw std::runtime_error("curl_global_init failed while loading SSH keys");
    }
  });
}

std::size_t append_body(char* ptr, std::size_t size, std::size_t count,
                        void* userdata) {
  const std::size_t bytes = size * count;
  static_cast<std::string*>(userdata)->append(ptr, bytes);
  return bytes;
}

std::string fetch_text(const std::string& url) {
  ensure_curl();
  CURL* curl = curl_easy_init();
  if (curl == nullptr) throw std::runtime_error("curl_easy_init failed loading SSH keys");
  std::string body;
  try {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "tailcat-cpp");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &append_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    const auto rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
      throw std::runtime_error(std::string("fetching SSH public keys: ") +
                               curl_easy_strerror(rc));
    }
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (status != 200L) {
      throw std::runtime_error("SSH public key source HTTP status " +
                               std::to_string(status));
    }
  } catch (...) {
    curl_easy_cleanup(curl);
    throw;
  }
  curl_easy_cleanup(curl);
  return body;
}

std::string read_file(const fs::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open SSH public key source: " + path.string());
  }
  std::ostringstream out;
  out << input.rdbuf();
  if (!input.good() && !input.eof()) {
    throw std::runtime_error("failed reading SSH public key source: " + path.string());
  }
  return out.str();
}

fs::path expand_home(std::string_view source) {
  if (source.size() < 2U || source[0] != '~' ||
      (source[1] != '/' && source[1] != '\\')) {
    return fs::path(std::string(source));
  }
#ifdef _WIN32
  const char* home = std::getenv("USERPROFILE");
#else
  const char* home = std::getenv("HOME");
#endif
  if (home == nullptr || *home == '\0') {
    throw std::runtime_error("cannot expand ~ in SSH public key path");
  }
  return fs::path(home) / std::string(source.substr(2U));
}

bool github_name(std::string_view source, std::string& username) {
  constexpr std::string_view suffix = "@github";
  if (!source.ends_with(suffix)) return false;
  source.remove_suffix(suffix.size());
  if (source.empty() || source.size() > 39U || source.front() == '-' ||
      source.back() == '-') {
    throw std::invalid_argument("invalid GitHub username in SSH public key source");
  }
  for (const char c : source) {
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-')) {
      throw std::invalid_argument("invalid GitHub username in SSH public key source");
    }
  }
  username.assign(source);
  return true;
}

bool looks_like_literal_key(std::string_view source) {
  if (source.find('\n') != std::string_view::npos ||
      source.find('\r') != std::string_view::npos) {
    return true;
  }
  std::istringstream input{std::string(source)};
  std::string type;
  input >> type;
  return !type.empty() && ssh_key_type_from_name(type.c_str()) != SSH_KEYTYPE_UNKNOWN;
}

std::vector<std::string> split_sources(std::string_view sources) {
  std::vector<std::string> out;
  std::size_t start = 0U;
  while (start <= sources.size()) {
    const auto comma = sources.find(',', start);
    const auto end = comma == std::string_view::npos ? sources.size() : comma;
    auto item = trim(sources.substr(start, end - start));
    if (item.empty()) throw std::invalid_argument("empty SSH public key source");
    out.push_back(std::move(item));
    if (comma == std::string_view::npos) break;
    start = comma + 1U;
  }
  return out;
}

void append_unique(std::vector<std::string>& target,
                   const std::vector<std::string>& keys) {
  for (const auto& key : keys) {
    if (std::find(target.begin(), target.end(), key) == target.end()) {
      target.push_back(key);
    }
  }
}

}  // namespace

std::vector<std::string> parse_ssh_authorized_keys_text(std::string_view text) {
  std::vector<std::string> keys;
  std::size_t line_number = 0U;
  while (!text.empty()) {
    ++line_number;
    const auto newline = text.find('\n');
    auto line = text.substr(0, newline == std::string_view::npos ? text.size() : newline);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1U);
    const auto cleaned = trim(line);
    if (!cleaned.empty() && cleaned.front() != '#') {
      std::istringstream input(cleaned);
      std::string type;
      std::string encoded;
      input >> type >> encoded;
      const auto key_type = ssh_key_type_from_name(type.c_str());
      if (type.empty() || encoded.empty() || key_type == SSH_KEYTYPE_UNKNOWN) {
        throw std::invalid_argument(
            "authorized keys line " + std::to_string(line_number) +
            ": options are not supported or key type is invalid");
      }

      ssh_key key = nullptr;
      if (ssh_pki_import_pubkey_base64(encoded.c_str(), key_type, &key) != SSH_OK ||
          key == nullptr) {
        throw std::invalid_argument("authorized keys line " +
                                    std::to_string(line_number) +
                                    ": invalid public key");
      }
      char* canonical = nullptr;
      const int rc = ssh_pki_export_pubkey_base64(key, &canonical);
      ssh_key_free(key);
      if (rc != SSH_OK || canonical == nullptr) {
        if (canonical != nullptr) ssh_string_free_char(canonical);
        throw std::runtime_error("failed to canonicalize SSH public key");
      }
      std::string blob(canonical);
      ssh_string_free_char(canonical);
      if (std::find(keys.begin(), keys.end(), blob) == keys.end()) {
        keys.push_back(std::move(blob));
      }
    }
    if (newline == std::string_view::npos) break;
    text.remove_prefix(newline + 1U);
  }
  if (keys.empty()) throw std::invalid_argument("no SSH public keys found");
  return keys;
}

std::vector<std::string> load_ssh_authorized_key_blobs(std::string_view sources) {
  if (trim(sources).empty()) {
    throw std::invalid_argument("--ssh-authorized-keys requires a value");
  }
  std::vector<std::string> result;
  for (const auto& source : split_sources(sources)) {
    std::string text;
    std::string username;
    if (github_name(source, username)) {
      text = fetch_text("https://github.com/" + username + ".keys");
    } else if (looks_like_literal_key(source)) {
      text = source;
    } else {
      text = read_file(expand_home(source));
    }
    append_unique(result, parse_ssh_authorized_keys_text(text));
  }
  if (result.empty()) throw std::invalid_argument("no SSH public keys found");
  return result;
}

}  // namespace tailcat
