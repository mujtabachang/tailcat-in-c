#pragma once

#include "tailcat/common.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace tailcat {

enum class MessageType : std::uint8_t {
  Open = 1,
  Data = 2,
  Close = 3,
  Error = 4,
  Ping = 5,
  Pong = 6,
};

struct Message {
  MessageType type = MessageType::Data;
  std::uint32_t stream_id = 0;
  std::vector<std::uint8_t> payload;
};

std::vector<std::uint8_t> encode_message(const Message& message);
Message decode_message(std::span<const std::uint8_t> bytes);

std::string payload_string(const Message& message);
Message make_text_message(MessageType type, std::uint32_t stream_id, std::string_view text);

}  // namespace tailcat
