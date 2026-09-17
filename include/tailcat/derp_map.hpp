// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "tailcat/protocol.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace tailcat {

struct DerpMap {
  std::vector<DerpRegion> regions;
};

DerpMap fetch_derp_map(const std::string& url = "https://tailcat.dev/derpmap.json");
DerpRegion select_derp_region(const DerpMap& map);
DerpRegion region_by_id(const DerpMap& map, std::int64_t region_id);
DerpNode primary_derp_node(const DerpRegion& region);

}  // namespace tailcat
