// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/ssh_command.hpp"

#include <cassert>
#include <string>

int main() {
  const std::string address = "tc0123456789abcdefghijklmnopqrstuvwxyz";
  const auto host1 = tailcat::ssh_destination_host(address);
  const auto host2 = tailcat::ssh_destination_host(address);
  assert(host1 == host2);
  assert(host1.rfind("tailcat-", 0) == 0);
  assert(host1.size() == std::string("tailcat-").size() + 16U);

  const auto proxy = tailcat::ssh_proxy_command(
      "/tmp/tail cat", address, "22", true, "client-default");
  assert(proxy.find(address) != std::string::npos);
  assert(proxy.find("22") != std::string::npos);
  assert(proxy.find("--verbose") != std::string::npos);
  assert(proxy.find("--key=client-default") != std::string::npos);
#ifdef _WIN32
  assert(proxy.find("\"/tmp/tail cat\"") != std::string::npos);
#else
  assert(proxy.find("'/tmp/tail cat'") != std::string::npos);
#endif
  return 0;
}
