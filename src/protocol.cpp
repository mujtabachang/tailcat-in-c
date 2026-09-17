// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat/protocol.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace tailcat {
namespace {

[[noreturn]] void parse_error(const std::string& message) { throw std::runtime_error("tailcat address: " + message); }

bool all_zero(const Key32& key) noexcept {
  return std::all_of(key.begin(), key.end(), [](std::uint8_t b) { return b == 0; });
}

std::string base64url_encode(const std::vector<std::uint8_t>& in) {
  static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve((in.size() * 4U + 2U) / 3U);
  std::size_t i = 0;
  while (i + 3U <= in.size()) {
    const std::uint32_t v = (static_cast<std::uint32_t>(in[i]) << 16U) |
                            (static_cast<std::uint32_t>(in[i + 1U]) << 8U) |
                            static_cast<std::uint32_t>(in[i + 2U]);
    out.push_back(alphabet[(v >> 18U) & 63U]);
    out.push_back(alphabet[(v >> 12U) & 63U]);
    out.push_back(alphabet[(v >> 6U) & 63U]);
    out.push_back(alphabet[v & 63U]);
    i += 3U;
  }
  const std::size_t remain = in.size() - i;
  if (remain == 1U) {
    const std::uint32_t v = static_cast<std::uint32_t>(in[i]) << 16U;
    out.push_back(alphabet[(v >> 18U) & 63U]);
    out.push_back(alphabet[(v >> 12U) & 63U]);
  } else if (remain == 2U) {
    const std::uint32_t v = (static_cast<std::uint32_t>(in[i]) << 16U) |
                            (static_cast<std::uint32_t>(in[i + 1U]) << 8U);
    out.push_back(alphabet[(v >> 18U) & 63U]);
    out.push_back(alphabet[(v >> 12U) & 63U]);
    out.push_back(alphabet[(v >> 6U) & 63U]);
  }
  return out;
}

std::uint8_t b64_value(char c) {
  if (c >= 'A' && c <= 'Z') return static_cast<std::uint8_t>(c - 'A');
  if (c >= 'a' && c <= 'z') return static_cast<std::uint8_t>(26 + c - 'a');
  if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(52 + c - '0');
  if (c == '-') return 62;
  if (c == '_') return 63;
  throw std::runtime_error("invalid base64url character");
}

std::vector<std::uint8_t> base64url_decode(std::string_view text) {
  if (text.empty() || text.find('=') != std::string_view::npos || text.size() % 4U == 1U) {
    throw std::runtime_error("invalid base64url length or padding");
  }
  std::vector<std::uint8_t> out;
  out.reserve(text.size() * 3U / 4U + 2U);
  std::size_t i = 0;
  while (i + 4U <= text.size()) {
    const std::uint32_t v = (static_cast<std::uint32_t>(b64_value(text[i])) << 18U) |
                            (static_cast<std::uint32_t>(b64_value(text[i + 1U])) << 12U) |
                            (static_cast<std::uint32_t>(b64_value(text[i + 2U])) << 6U) |
                            static_cast<std::uint32_t>(b64_value(text[i + 3U]));
    out.push_back(static_cast<std::uint8_t>((v >> 16U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((v >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(v & 0xffU));
    i += 4U;
  }
  const std::size_t remain = text.size() - i;
  if (remain == 2U) {
    const std::uint32_t v = (static_cast<std::uint32_t>(b64_value(text[i])) << 18U) |
                            (static_cast<std::uint32_t>(b64_value(text[i + 1U])) << 12U);
    out.push_back(static_cast<std::uint8_t>((v >> 16U) & 0xffU));
  } else if (remain == 3U) {
    const std::uint32_t v = (static_cast<std::uint32_t>(b64_value(text[i])) << 18U) |
                            (static_cast<std::uint32_t>(b64_value(text[i + 1U])) << 12U) |
                            (static_cast<std::uint32_t>(b64_value(text[i + 2U])) << 6U);
    out.push_back(static_cast<std::uint8_t>((v >> 16U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((v >> 8U) & 0xffU));
  }
  return out;
}

class CborReader {
 public:
  explicit CborReader(const std::vector<std::uint8_t>& data) : data_(data) {}

  bool done() const noexcept { return pos_ == data_.size(); }

  std::uint64_t map_size() { return expect_major(5U); }
  std::uint64_t array_size() { return expect_major(4U); }
  std::string text() {
    const auto len = expect_major(3U);
    require_len(len);
    const auto start = pos_;
    pos_ += static_cast<std::size_t>(len);
    return std::string(reinterpret_cast<const char*>(data_.data() + start), static_cast<std::size_t>(len));
  }
  std::vector<std::uint8_t> bytes() {
    const auto len = expect_major(2U);
    require_len(len);
    const auto start = pos_;
    pos_ += static_cast<std::size_t>(len);
    return std::vector<std::uint8_t>(data_.begin() + static_cast<std::ptrdiff_t>(start),
                                     data_.begin() + static_cast<std::ptrdiff_t>(pos_));
  }
  std::int64_t integer() {
    const auto [major, value] = head();
    if (major == 0U) {
      if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) parse_error("integer overflow");
      return static_cast<std::int64_t>(value);
    }
    if (major == 1U) {
      if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) parse_error("negative integer overflow");
      return -1 - static_cast<std::int64_t>(value);
    }
    parse_error("expected integer");
  }
  bool boolean() {
    require(1U);
    const auto b = data_[pos_++];
    if (b == 0xf4U) return false;
    if (b == 0xf5U) return true;
    parse_error("expected boolean");
  }
  void skip() {
    const auto [major, value] = head();
    switch (major) {
      case 0U:
      case 1U:
      case 7U:
        return;
      case 2U:
      case 3U:
        require_len(value);
        pos_ += static_cast<std::size_t>(value);
        return;
      case 4U:
        for (std::uint64_t i = 0; i < value; ++i) skip();
        return;
      case 5U:
        for (std::uint64_t i = 0; i < value; ++i) { skip(); skip(); }
        return;
      case 6U:
        skip();
        return;
      default:
        parse_error("unsupported CBOR major type");
    }
  }

 private:
  std::pair<std::uint8_t, std::uint64_t> head() {
    require(1U);
    const std::uint8_t first = data_[pos_++];
    const std::uint8_t major = static_cast<std::uint8_t>(first >> 5U);
    const std::uint8_t ai = static_cast<std::uint8_t>(first & 31U);
    if (ai < 24U) return {major, ai};
    if (ai == 31U) parse_error("indefinite-length CBOR is not accepted");
    const std::size_t n = ai == 24U ? 1U : ai == 25U ? 2U : ai == 26U ? 4U : ai == 27U ? 8U : 0U;
    if (n == 0U) parse_error("invalid CBOR additional information");
    require(n);
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < n; ++i) value = (value << 8U) | data_[pos_++];
    return {major, value};
  }
  std::uint64_t expect_major(std::uint8_t want) {
    const auto [major, value] = head();
    if (major != want) parse_error("unexpected CBOR type");
    return value;
  }
  void require(std::size_t n) const {
    if (n > data_.size() - pos_) parse_error("truncated CBOR");
  }
  void require_len(std::uint64_t n) const {
    if (n > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) parse_error("CBOR length overflow");
    require(static_cast<std::size_t>(n));
  }

  const std::vector<std::uint8_t>& data_;
  std::size_t pos_ = 0;
};

class CborWriter {
 public:
  void map(std::uint64_t n) { head(5U, n); }
  void array(std::uint64_t n) { head(4U, n); }
  void text(std::string_view s) {
    head(3U, static_cast<std::uint64_t>(s.size()));
    out_.insert(out_.end(), s.begin(), s.end());
  }
  void bytes(const Key32& b) {
    head(2U, b.size());
    out_.insert(out_.end(), b.begin(), b.end());
  }
  void integer(std::int64_t value) {
    if (value >= 0) head(0U, static_cast<std::uint64_t>(value));
    else head(1U, static_cast<std::uint64_t>(-(value + 1)));
  }
  void boolean(bool value) { out_.push_back(value ? 0xf5U : 0xf4U); }
  const std::vector<std::uint8_t>& data() const noexcept { return out_; }

 private:
  void head(std::uint8_t major, std::uint64_t value) {
    const auto prefix = static_cast<std::uint8_t>(major << 5U);
    if (value < 24U) {
      out_.push_back(static_cast<std::uint8_t>(prefix | static_cast<std::uint8_t>(value)));
    } else if (value <= 0xffU) {
      out_.push_back(static_cast<std::uint8_t>(prefix | 24U));
      out_.push_back(static_cast<std::uint8_t>(value));
    } else if (value <= 0xffffU) {
      out_.push_back(static_cast<std::uint8_t>(prefix | 25U));
      out_.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
      out_.push_back(static_cast<std::uint8_t>(value & 0xffU));
    } else if (value <= 0xffffffffULL) {
      out_.push_back(static_cast<std::uint8_t>(prefix | 26U));
      for (int shift = 24; shift >= 0; shift -= 8) out_.push_back(static_cast<std::uint8_t>((value >> static_cast<unsigned>(shift)) & 0xffU));
    } else {
      out_.push_back(static_cast<std::uint8_t>(prefix | 27U));
      for (int shift = 56; shift >= 0; shift -= 8) out_.push_back(static_cast<std::uint8_t>((value >> static_cast<unsigned>(shift)) & 0xffU));
    }
  }
  std::vector<std::uint8_t> out_;
};

Key32 key32(CborReader& r, const char* field) {
  const auto raw = r.bytes();
  if (raw.size() != 32U) parse_error(std::string(field) + " must be exactly 32 bytes");
  Key32 out{};
  std::copy(raw.begin(), raw.end(), out.begin());
  return out;
}

DerpNode read_node(CborReader& r) {
  DerpNode n;
  const auto count = r.map_size();
  for (std::uint64_t i = 0; i < count; ++i) {
    const auto key = r.text();
    if (key == "n") n.name = r.text();
    else if (key == "i") n.region_id = r.integer();
    else if (key == "h") n.host_name = r.text();
    else if (key == "t") n.cert_name = r.text();
    else if (key == "4") n.ipv4 = r.text();
    else if (key == "6") n.ipv6 = r.text();
    else if (key == "s") n.stun_port = r.integer();
    else if (key == "d") n.derp_port = r.integer();
    else if (key == "x") n.insecure_for_tests = r.boolean();
    else r.skip();
  }
  return n;
}

DerpRegion read_region(CborReader& r) {
  DerpRegion region;
  const auto count = r.map_size();
  for (std::uint64_t i = 0; i < count; ++i) {
    const auto key = r.text();
    if (key == "i") region.region_id = r.integer();
    else if (key == "c") region.region_code = r.text();
    else if (key == "m") region.region_name = r.text();
    else if (key == "N") {
      const auto n = r.array_size();
      region.nodes.reserve(static_cast<std::size_t>(n));
      for (std::uint64_t j = 0; j < n; ++j) region.nodes.push_back(read_node(r));
    } else r.skip();
  }
  for (auto& node : region.nodes) {
    if (node.region_id == 0) node.region_id = region.region_id;
  }
  return region;
}

void write_node(CborWriter& w, const DerpNode& n) {
  std::uint64_t count = 0;
  if (!n.name.empty()) ++count;
  if (n.region_id != 0) ++count;
  if (!n.host_name.empty()) ++count;
  if (!n.cert_name.empty()) ++count;
  if (!n.ipv4.empty()) ++count;
  if (!n.ipv6.empty()) ++count;
  if (n.stun_port != 0) ++count;
  if (n.derp_port != 0) ++count;
  if (n.insecure_for_tests) ++count;
  w.map(count);
  if (!n.name.empty()) { w.text("n"); w.text(n.name); }
  if (n.region_id != 0) { w.text("i"); w.integer(n.region_id); }
  if (!n.host_name.empty()) { w.text("h"); w.text(n.host_name); }
  if (!n.cert_name.empty()) { w.text("t"); w.text(n.cert_name); }
  if (!n.ipv4.empty()) { w.text("4"); w.text(n.ipv4); }
  if (!n.ipv6.empty()) { w.text("6"); w.text(n.ipv6); }
  if (n.stun_port != 0) { w.text("s"); w.integer(n.stun_port); }
  if (n.derp_port != 0) { w.text("d"); w.integer(n.derp_port); }
  if (n.insecure_for_tests) { w.text("x"); w.boolean(true); }
}

void write_region(CborWriter& w, const DerpRegion& r) {
  std::uint64_t count = 0;
  if (r.region_id != 0) ++count;
  if (!r.region_code.empty()) ++count;
  if (!r.region_name.empty()) ++count;
  if (!r.nodes.empty()) ++count;
  w.map(count);
  if (r.region_id != 0) { w.text("i"); w.integer(r.region_id); }
  if (!r.region_code.empty()) { w.text("c"); w.text(r.region_code); }
  if (!r.region_name.empty()) { w.text("m"); w.text(r.region_name); }
  if (!r.nodes.empty()) {
    w.text("N");
    w.array(static_cast<std::uint64_t>(r.nodes.size()));
    for (const auto& n : r.nodes) write_node(w, n);
  }
}

}  // namespace

ConnInfo parse_tailcat_addr(std::string_view addr) {
  if (!addr.starts_with("tc")) parse_error("doesn't start with \"tc\"");
  std::vector<std::uint8_t> raw;
  try {
    raw = base64url_decode(addr.substr(2));
  } catch (const std::exception& e) {
    parse_error(std::string("base64 decode: ") + e.what());
  }
  CborReader r(raw);
  ConnInfo info;
  bool have_public = false;
  const auto count = r.map_size();
  for (std::uint64_t i = 0; i < count; ++i) {
    const auto key = r.text();
    if (key == "p") { info.server_public = key32(r, "ServerPublic"); have_public = true; }
    else if (key == "k") info.server_disco_public = key32(r, "ServerDiscoPublic");
    else if (key == "q") info.preshared_key = key32(r, "PresharedKey");
    else if (key == "r") {
      const auto n = r.array_size();
      if (n > 1U) parse_error("more than one embedded DERP region");
      info.regions.reserve(static_cast<std::size_t>(n));
      for (std::uint64_t j = 0; j < n; ++j) info.regions.push_back(read_region(r));
    } else if (key == "i") info.region_id = r.integer();
    else r.skip();
  }
  if (!r.done()) parse_error("trailing CBOR data");
  if (!have_public || all_zero(info.server_public)) parse_error("missing or zero ServerPublic");
  if (info.server_disco_public && all_zero(*info.server_disco_public)) parse_error("zero ServerDiscoPublic");
  if (!info.regions.empty() && info.region_id == 0) info.region_id = info.regions.front().region_id;
  if (info.region_id == 0 && info.regions.empty()) parse_error("missing DERP region");
  return info;
}

std::string encode_tailcat_addr(const ConnInfo& info) {
  if (all_zero(info.server_public)) throw std::runtime_error("cannot encode zero ServerPublic");
  if (info.server_disco_public && all_zero(*info.server_disco_public)) throw std::runtime_error("cannot encode zero ServerDiscoPublic");
  std::uint64_t count = 1;
  if (info.server_disco_public) ++count;
  if (info.preshared_key) ++count;
  if (!info.regions.empty()) ++count;
  if (info.region_id != 0) ++count;
  CborWriter w;
  w.map(count);
  w.text("p"); w.bytes(info.server_public);
  if (info.server_disco_public) { w.text("k"); w.bytes(*info.server_disco_public); }
  if (info.preshared_key) { w.text("q"); w.bytes(*info.preshared_key); }
  if (!info.regions.empty()) {
    w.text("r");
    w.array(static_cast<std::uint64_t>(info.regions.size()));
    for (const auto& r : info.regions) write_region(w, r);
  }
  if (info.region_id != 0) { w.text("i"); w.integer(info.region_id); }
  return "tc" + base64url_encode(w.data());
}

std::vector<std::uint8_t> encode_meow_ping(const Key32& node_public, const Key32& disco_public) {
  std::vector<std::uint8_t> out;
  out.reserve(69U);
  out.insert(out.end(), {'m', 'e', 'o', 'w', 0x01U});
  out.insert(out.end(), node_public.begin(), node_public.end());
  out.insert(out.end(), disco_public.begin(), disco_public.end());
  return out;
}

std::vector<std::uint8_t> encode_meowed() { return {'m', 'e', 'o', 'w', 0x02U}; }

bool is_meow_packet(const std::vector<std::uint8_t>& packet) noexcept {
  return packet.size() >= 4U && packet[0] == 'm' && packet[1] == 'e' && packet[2] == 'o' && packet[3] == 'w';
}

bool is_meowed_packet(const std::vector<std::uint8_t>& packet) noexcept {
  return packet.size() >= 5U && is_meow_packet(packet) && packet[4] == 0x02U;
}

bool parse_meow_ping(const std::vector<std::uint8_t>& packet, Key32& node_public, Key32& disco_public) noexcept {
  if (packet.size() < 69U || !is_meow_packet(packet) || packet[4] != 0x01U) return false;
  std::copy_n(packet.begin() + 5, 32, node_public.begin());
  std::copy_n(packet.begin() + 37, 32, disco_public.begin());
  if (all_zero(disco_public)) {
    node_public.fill(0);
    disco_public.fill(0);
    return false;
  }
  return true;
}

}  // namespace tailcat
