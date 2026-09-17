// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/data_plane.hpp"

#include <memory>

namespace tailcat {

// Terminates SSH directly on Tailcat TCP port 22. Unlike ordinary served TCP
// ports this does not connect to a host-side sshd; SSH protocol handling and
// shell/exec process management stay inside the Tailcat process.
class EmbeddedSshServer {
 public:
  explicit EmbeddedSshServer(TailcatServerDataPlane& data_plane,
                             bool verbose = false);
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
