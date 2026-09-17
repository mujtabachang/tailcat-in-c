#include "tailcat/protocol.hpp"

namespace tailcat {

std::vector<std::uint8_t> encode_message(const Message& m) {
  if (m.payload.size() > 60000) throw Error("protocol payload too large");
  std::vector<std::uint8_t> out; out.reserve(6 + m.payload.size());
  out.push_back(1); out.push_back(static_cast<std::uint8_t>(m.type)); append_be32(out,m.stream_id); out.insert(out.end(),m.payload.begin(),m.payload.end()); return out;
}
Message decode_message(std::span<const std::uint8_t> b) {
  if(b.size()<6||b[0]!=1)throw Error("invalid tailcat protocol packet"); Message m; m.type=static_cast<MessageType>(b[1]); m.stream_id=read_be32(b.data()+2); m.payload.assign(b.begin()+6,b.end()); return m;
}
std::string payload_string(const Message& m){return std::string(reinterpret_cast<const char*>(m.payload.data()),m.payload.size());}
Message make_text_message(MessageType t,std::uint32_t id,std::string_view text){Message m; m.type=t;m.stream_id=id;m.payload.assign(text.begin(),text.end());return m;}

}  // namespace tailcat
