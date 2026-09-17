// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/crypto.hpp"
#include "tailcat/protocol.hpp"

#include <optional>
#include <string>

namespace tailcat {

struct SavedTailcatKey {
  NodeKeyPair identity;
  std::optional<Key32> preshared_key;
  std::int64_t region_id = 0;
};

SavedTailcatKey new_saved_tailcat_key(bool use_psk = true,
                                      std::int64_t region_id = 0);
SavedTailcatKey load_saved_tailcat_key(const std::string& path);
void save_tailcat_key(const std::string& path, const SavedTailcatKey& key);

}  // namespace tailcat
