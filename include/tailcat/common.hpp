#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace tailcat {

using Key32 = std::array<std::uint8_t, 32>;
using Nonce24 = std::array<std::uint8_t, 24>;

class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

std::string base64url_encode(std::span<const std::uint8_t> input);
std::vector<std::uint8_t> base64url_decode(std::string_view input);
std::string hex(std::span<const std::uint8_t> input);

std::uint32_t read_be32(const std::uint8_t* p);
void append_be32(std::vector<std::uint8_t>& out, std::uint32_t v);
std::uint16_t read_be16(const std::uint8_t* p);
void append_be16(std::vector<std::uint8_t>& out, std::uint16_t v);

}  // namespace tailcat
