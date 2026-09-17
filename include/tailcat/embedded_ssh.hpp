// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/data_plane.hpp"

#include <memory>
#include <string>
#include <vector>

namespace tailcat {

struct EmbeddedSshOptions {
  // Upstream's explicit no-auth-ssh service relies on the already-authenticated
  // Tailcat/WireGuard peer identity and permits SSH's "none" auth method.
  bool allow_none = false;

  // Canonical public-key base64 blobs accepted for SSH public-key auth. The
  // ordinary "ssh" service requires at least one key; no-auth-ssh leaves this
  // empty and sets allow_none instead.
  std::vector<std::string> authorized_key_blobs;

  bool verbose = false;
};

// Terminates SSH directly on Tailcat TCP port 22. Unlike ordinary served TCP
// ports this does not connect to a host-side sshd; SSH protocol handling and
// shell/exec process management stay inside the Tailcat process.
class EmbeddedSshServer {
 public:
  explicit EmbeddedSshServer(TailcatServerDataPlane& data_plane,
                             EmbeddedSshOptions options = {});
  ~EmbeddedSshServer();
  EmbeddedSshServer(const EmbeddedSshServer&) = delete;
  EmbeddedSshServer& operator=(const EmbeddedSshServer&) = delete;

  // Pump newly accepted Tailcat streams and bytes between lwIP and the
  // in-process SSH engine. TailcatServerDataPlane::pump_for must be called by
  // the owner before this method.
  void poll();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace tailcat
