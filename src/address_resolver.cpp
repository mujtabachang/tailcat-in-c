// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/address_resolver.hpp"

#include "tailcat/protocol.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <windns.h>
#else
#include <arpa/nameser.h>
#include <resolv.h>
#endif

namespace tailcat {
namespace {

constexpr std::string_view kTxtPrefix = "tailcat=";

void validate_tailcat_address(std::string_view value) {
  (void)parse_tailcat_addr(value);
}

bool label_is_tailcat_address(std::string_view label) {
  if (!label.starts_with("tc")) return false;
  try {
    validate_tailcat_address(label);
    return true;
  } catch (...) {
    return false;
  }
}

std::vector<std::string> query_txt_records(std::string_view dns_name) {
#ifdef _WIN32
  DNS_RECORD* records = nullptr;
  const auto name = std::string(dns_name);
  const DNS_STATUS status = DnsQuery_A(name.c_str(), DNS_TYPE_TEXT,
                                       DNS_QUERY_STANDARD, nullptr, &records,
                                       nullptr);
  if (status != ERROR_SUCCESS) {
    throw std::runtime_error("DNS TXT lookup failed for " + name +
                             " (status " + std::to_string(status) + ")");
  }

  std::vector<std::string> result;
  for (auto* record = records; record != nullptr; record = record->pNext) {
    if (record->wType != DNS_TYPE_TEXT) continue;
    std::string value;
    for (DWORD i = 0; i < record->Data.TXT.dwStringCount; ++i) {
      if (record->Data.TXT.pStringArray[i] != nullptr) {
        value += record->Data.TXT.pStringArray[i];
      }
    }
    result.push_back(std::move(value));
  }
  DnsRecordListFree(records, DnsFreeRecordList);
  return result;
#else
  std::array<unsigned char, 65536> response{};
  const auto name = std::string(dns_name);
  const int length = res_query(name.c_str(), ns_c_in, ns_t_txt,
                               response.data(),
                               static_cast<int>(response.size()));
  if (length < 0) {
    throw std::runtime_error("DNS TXT lookup failed for " + name);
  }
  const auto size = static_cast<std::size_t>(length);
  if (size < 12U) throw std::runtime_error("short DNS TXT response for " + name);

  const auto read16 = [&](std::size_t offset) -> std::uint16_t {
    if (offset + 2U > size) throw std::runtime_error("truncated DNS TXT response");
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(response[offset]) << 8U) |
        static_cast<std::uint16_t>(response[offset + 1U]));
  };
  const auto skip_name = [&](std::size_t& offset) {
    for (;;) {
      if (offset >= size) throw std::runtime_error("truncated DNS name");
      const auto label = response[offset++];
      if (label == 0U) return;
      if ((label & 0xc0U) == 0xc0U) {
        if (offset >= size) throw std::runtime_error("truncated DNS compression pointer");
        ++offset;
        return;
      }
      if ((label & 0xc0U) != 0U || label > 63U ||
          offset + static_cast<std::size_t>(label) > size) {
        throw std::runtime_error("invalid DNS name in TXT response");
      }
      offset += static_cast<std::size_t>(label);
    }
  };

  std::size_t offset = 12U;
  const auto questions = read16(4U);
  const auto answers = read16(6U);
  for (std::uint16_t i = 0; i < questions; ++i) {
    skip_name(offset);
    if (offset + 4U > size) throw std::runtime_error("truncated DNS question");
    offset += 4U;
  }

  std::vector<std::string> result;
  for (std::uint16_t i = 0; i < answers; ++i) {
    skip_name(offset);
    if (offset + 10U > size) throw std::runtime_error("truncated DNS answer");
    const auto type = read16(offset);
    const auto klass = read16(offset + 2U);
    const auto data_length = read16(offset + 8U);
    offset += 10U;
    const auto end = offset + static_cast<std::size_t>(data_length);
    if (end > size) throw std::runtime_error("truncated DNS answer data");
    if (type == ns_t_txt && klass == ns_c_in) {
      std::string value;
      while (offset < end) {
        const auto part_length = static_cast<std::size_t>(response[offset++]);
        if (offset + part_length > end) {
          throw std::runtime_error("invalid DNS TXT string length");
        }
        value.append(reinterpret_cast<const char*>(response.data() + offset),
                     part_length);
        offset += part_length;
      }
      result.push_back(std::move(value));
    } else {
      offset = end;
    }
  }
  return result;
#endif
}

}  // namespace

ResolvedTailcatAddress classify_tailcat_address_argument(std::string_view value) {
  if (value.empty()) throw std::invalid_argument("empty Tailcat destination");
  try {
    validate_tailcat_address(value);
    return ResolvedTailcatAddress{std::string(value), {}, false};
  } catch (...) {
  }

  if (value.find('.') == std::string_view::npos) {
    throw std::invalid_argument("invalid Tailcat address or DNS name: " +
                                std::string(value));
  }

  std::size_t start = 0U;
  while (start <= value.size()) {
    const auto dot = value.find('.', start);
    const auto end = dot == std::string_view::npos ? value.size() : dot;
    const auto label = value.substr(start, end - start);
    if (label_is_tailcat_address(label)) {
      throw std::invalid_argument(
          "refusing DNS lookup: destination contains a Tailcat address as a DNS label");
    }
    if (dot == std::string_view::npos) break;
    start = dot + 1U;
  }

  return ResolvedTailcatAddress{{}, std::string(value), true};
}

std::string tailcat_address_from_txt(const std::vector<std::string>& records) {
  std::string selected;
  for (const auto& record : records) {
    if (!std::string_view(record).starts_with(kTxtPrefix)) continue;
    const auto value = std::string_view(record).substr(kTxtPrefix.size());
    if (value.empty()) throw std::runtime_error("empty tailcat= DNS TXT record");
    try {
      validate_tailcat_address(value);
    } catch (const std::exception& e) {
      throw std::runtime_error(std::string("invalid tailcat= DNS TXT record: ") +
                               e.what());
    }
    if (selected.empty()) {
      selected = value;
    } else if (selected != value) {
      throw std::runtime_error("DNS name has conflicting tailcat= TXT records");
    }
  }
  if (selected.empty()) {
    throw std::runtime_error("DNS name has no tailcat= TXT record");
  }
  return selected;
}

ResolvedTailcatAddress resolve_tailcat_address_argument(std::string_view value) {
  auto classified = classify_tailcat_address_argument(value);
  if (!classified.via_dns) return classified;
  classified.address = tailcat_address_from_txt(query_txt_records(classified.dns_name));
  return classified;
}

}  // namespace tailcat
