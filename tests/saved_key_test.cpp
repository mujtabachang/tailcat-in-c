// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/crypto.hpp"
#include "tailcat/saved_key.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

int main() {
  tailcat::initialize_crypto();
  const auto original = tailcat::new_saved_tailcat_key(true, 7);
  const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto path = std::filesystem::temp_directory_path() /
                    ("tailcat-key-" + std::to_string(nonce) + ".json");
  tailcat::save_tailcat_key(path.string(), original);

  const auto loaded = tailcat::load_saved_tailcat_key(path.string());
  assert(loaded.identity.private_key == original.identity.private_key);
  assert(loaded.identity.public_key == original.identity.public_key);
  assert(loaded.preshared_key == original.preshared_key);
  assert(loaded.region_id == 7);

  std::ifstream input(path, std::ios::binary);
  const std::string json((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
  assert(json.find("privkey:") != std::string::npos);
  assert(json.find("nodekey:") != std::string::npos);
  assert(json.find("discokey:") != std::string::npos);
  assert(json.find("psk:") != std::string::npos);
  std::filesystem::remove(path);
  return 0;
}
