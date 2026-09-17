// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace tailcat {

struct ResolvedTailcatAddress {
  std::string address;
  std::string dns_name;
  bool via_dns = false;
};

// Classifies a destination without network I/O. Direct valid tc... addresses
// are returned as-is. DNS-looking names are marked for TXT lookup, except that
// a DNS label containing a valid Tailcat address is rejected to avoid leaking a
// pasted address in a DNS query.
ResolvedTailcatAddress classify_tailcat_address_argument(std::string_view value);

// Extracts and validates one tailcat=<tc...> value from DNS TXT records.
std::string tailcat_address_from_txt(const std::vector<std::string>& records);

// Resolves a direct Tailcat address or a DNS name whose TXT records contain a
// tailcat= address. The result records whether public DNS was consulted.
ResolvedTailcatAddress resolve_tailcat_address_argument(std::string_view value);

}  // namespace tailcat
