// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/cli.hpp"
#include "tailcat/platform.hpp"

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
  try {
    tailcat::initialize_platform();
    const auto cli = tailcat::parse_command_line(argc, argv);
    const int rc = tailcat::run(cli);
    tailcat::shutdown_platform();
    return rc;
  } catch (const std::exception& e) {
    tailcat::shutdown_platform();
    std::cerr << "tailcat: " << e.what() << '\n';
    return 1;
  }
}
