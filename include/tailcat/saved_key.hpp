// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/crypto.hpp"
#include "tailcat/protocol.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

// Upstream-compatible named-key location. Names without a path separator are
// stored under the user's config directory as
//   tailcat/keys/<name>.private.json
// while explicit paths are returned unchanged.
std::string tailcat_keys_dir();
std::string resolve_tailcat_key_path(const std::string& name_or_path);
bool saved_tailcat_key_exists(const std::string& name_or_path);
std::vector<std::string> list_saved_tailcat_keys();
void delete_saved_tailcat_key(const std::string& name_or_path);

// Typed text forms used by upstream Tailcat and its --allow flag.
std::string node_public_text(const Key32& key);
Key32 parse_node_public_text(std::string_view text);

}  // namespace tailcat
