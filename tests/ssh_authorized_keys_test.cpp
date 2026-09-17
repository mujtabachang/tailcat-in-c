// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/ssh_authorized_keys.hpp"

#include <cassert>
#include <stdexcept>
#include <string>

int main() {
  constexpr const char* kKey =
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIujq/HWVfplmh7TmVZOS7CslRk3RPyER6vlQX0o+E5W test@example\n";

  const auto parsed = tailcat::parse_ssh_authorized_keys_text(
      std::string("# comment\n\n") + kKey + kKey);
  assert(parsed.size() == 1U);
  assert(parsed.front() ==
         "AAAAC3NzaC1lZDI1NTE5AAAAIIujq/HWVfplmh7TmVZOS7CslRk3RPyER6vlQX0o+E5W");

  bool rejected_options = false;
  try {
    (void)tailcat::parse_ssh_authorized_keys_text(
        "no-port-forwarding ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIIujq/HWVfplmh7TmVZOS7CslRk3RPyER6vlQX0o+E5W\n");
  } catch (const std::invalid_argument&) {
    rejected_options = true;
  }
  assert(rejected_options);

  bool rejected_empty = false;
  try {
    (void)tailcat::parse_ssh_authorized_keys_text("# only a comment\n");
  } catch (const std::invalid_argument&) {
    rejected_empty = true;
  }
  assert(rejected_empty);
  return 0;
}
