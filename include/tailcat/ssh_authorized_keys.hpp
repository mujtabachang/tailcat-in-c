// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace tailcat {

// Parse OpenSSH authorized_keys text and return canonical public-key base64
// blobs. Blank lines and comments are ignored. Authorized-key options are
// rejected because Tailcat does not implement their restrictions.
std::vector<std::string> parse_ssh_authorized_keys_text(std::string_view text);

// Load a comma-separated list of SSH public-key sources. A source may be a
// local authorized_keys/public-key file, a literal OpenSSH public-key line, or
// a GitHub identity such as "alice@github" (loaded from github.com/alice.keys).
// All sources are validated eagerly; an empty result is an error.
std::vector<std::string> load_ssh_authorized_key_blobs(std::string_view sources);

}  // namespace tailcat
