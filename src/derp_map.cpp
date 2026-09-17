// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/derp_map.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <string>

namespace tailcat {
namespace {

void ensure_curl() {
  static std::once_flag once;
  std::call_once(once, [] {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
      throw std::runtime_error("curl_global_init failed");
    }
  });
}

std::size_t append_body(char* ptr, std::size_t size, std::size_t count, void* userdata) {
  const std::size_t bytes = size * count;
  auto* out = static_cast<std::string*>(userdata);
  out->append(ptr, bytes);
  return bytes;
}

std::int64_t integer_or(const nlohmann::json& j, const char* key, std::int64_t fallback = 0) {
  const auto it = j.find(key);
  if (it == j.end() || it->is_null()) return fallback;
  if (it->is_number_integer()) return it->get<std::int64_t>();
  if (it->is_number_unsigned()) return static_cast<std::int64_t>(it->get<std::uint64_t>());
  return fallback;
}

std::string string_or(const nlohmann::json& j, const char* key) {
  const auto it = j.find(key);
  if (it == j.end() || !it->is_string()) return {};
  return it->get<std::string>();
}

bool bool_or(const nlohmann::json& j, const char* key) {
  const auto it = j.find(key);
  return it != j.end() && it->is_boolean() && it->get<bool>();
}

DerpRegion parse_region(const nlohmann::json& j, std::int64_t fallback_id) {
  DerpRegion region;
  region.region_id = integer_or(j, "RegionID", fallback_id);
  region.region_code = string_or(j, "RegionCode");
  region.region_name = string_or(j, "RegionName");
  const auto nodes_it = j.find("Nodes");
  if (nodes_it != j.end() && nodes_it->is_array()) {
    for (const auto& nj : *nodes_it) {
      if (!nj.is_object() || bool_or(nj, "STUNOnly")) continue;
      DerpNode node;
      node.name = string_or(nj, "Name");
      node.region_id = integer_or(nj, "RegionID", region.region_id);
      node.host_name = string_or(nj, "HostName");
      node.cert_name = string_or(nj, "CertName");
      node.ipv4 = string_or(nj, "IPv4");
      node.ipv6 = string_or(nj, "IPv6");
      node.stun_port = integer_or(nj, "STUNPort");
      node.derp_port = integer_or(nj, "DERPPort");
      node.insecure_for_tests = bool_or(nj, "InsecureForTests");
      if (!node.host_name.empty()) region.nodes.push_back(std::move(node));
    }
  }
  return region;
}

}  // namespace

DerpMap fetch_derp_map(const std::string& url) {
  ensure_curl();
  CURL* curl = curl_easy_init();
  if (curl == nullptr) throw std::runtime_error("curl_easy_init failed fetching DERP map");
  std::string body;
  try {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "tailcat-cpp");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &append_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    const auto rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) throw std::runtime_error(std::string("fetching DERP map: ") + curl_easy_strerror(rc));
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (status != 200L) throw std::runtime_error("DERP map HTTP status " + std::to_string(status));
  } catch (...) {
    curl_easy_cleanup(curl);
    throw;
  }
  curl_easy_cleanup(curl);

  const auto root = nlohmann::json::parse(body);
  const auto regions_it = root.find("Regions");
  if (regions_it == root.end() || !regions_it->is_object()) {
    throw std::runtime_error("DERP map has no Regions object");
  }
  DerpMap map;
  for (auto it = regions_it->begin(); it != regions_it->end(); ++it) {
    std::int64_t fallback_id = 0;
    try {
      fallback_id = std::stoll(it.key());
    } catch (const std::exception&) {
      continue;
    }
    if (!it.value().is_object()) continue;
    auto region = parse_region(it.value(), fallback_id);
    if (region.region_id != 0 && !region.nodes.empty()) map.regions.push_back(std::move(region));
  }
  std::sort(map.regions.begin(), map.regions.end(),
            [](const DerpRegion& a, const DerpRegion& b) { return a.region_id < b.region_id; });
  if (map.regions.empty()) throw std::runtime_error("DERP map contains no usable relay regions");
  return map;
}

DerpRegion select_derp_region(const DerpMap& map) {
  if (map.regions.empty()) throw std::runtime_error("cannot select from an empty DERP map");
  // Region choice affects latency, not wire compatibility. Start with the first
  // usable region; a netcheck/STUN latency scorer can replace this policy without
  // changing addresses, DERP, WireGuard, or stream semantics.
  return map.regions.front();
}

DerpRegion region_by_id(const DerpMap& map, std::int64_t region_id) {
  const auto it = std::find_if(map.regions.begin(), map.regions.end(),
                               [region_id](const DerpRegion& r) { return r.region_id == region_id; });
  if (it == map.regions.end()) throw std::runtime_error("DERP region " + std::to_string(region_id) + " is not in map");
  return *it;
}

DerpNode primary_derp_node(const DerpRegion& region) {
  if (region.nodes.empty()) throw std::runtime_error("DERP region has no relay nodes");
  return region.nodes.front();
}

}  // namespace tailcat
