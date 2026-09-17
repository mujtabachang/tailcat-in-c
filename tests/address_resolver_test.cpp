// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/address_resolver.hpp"

#include <cassert>
#include <stdexcept>
#include <string>
#include <vector>

int main() {
  const std::string address =
      "tcomFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCg";

  const auto direct = tailcat::classify_tailcat_address_argument(address);
  assert(!direct.via_dns);
  assert(direct.address == address);
  assert(direct.dns_name.empty());

  const auto dns = tailcat::classify_tailcat_address_argument("cat.example.com");
  assert(dns.via_dns);
  assert(dns.address.empty());
  assert(dns.dns_name == "cat.example.com");

  bool leaked_label_rejected = false;
  try {
    (void)tailcat::classify_tailcat_address_argument(address + ".example.com");
  } catch (const std::invalid_argument&) {
    leaked_label_rejected = true;
  }
  assert(leaked_label_rejected);

  bool invalid_nondns_rejected = false;
  try {
    (void)tailcat::classify_tailcat_address_argument("tc-not-valid");
  } catch (const std::invalid_argument&) {
    invalid_nondns_rejected = true;
  }
  assert(invalid_nondns_rejected);

  assert(tailcat::tailcat_address_from_txt(
             {"hello=world", "tailcat=" + address}) == address);
  assert(tailcat::tailcat_address_from_txt(
             {"tailcat=" + address, "tailcat=" + address}) == address);

  bool conflicting = false;
  try {
    (void)tailcat::tailcat_address_from_txt(
        {"tailcat=" + address,
         "tailcat=tcomFwWCAAAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH2FpCw"});
  } catch (const std::runtime_error&) {
    conflicting = true;
  }
  assert(conflicting);

  bool missing = false;
  try {
    (void)tailcat::tailcat_address_from_txt({"hello=world"});
  } catch (const std::runtime_error&) {
    missing = true;
  }
  assert(missing);
  return 0;
}
