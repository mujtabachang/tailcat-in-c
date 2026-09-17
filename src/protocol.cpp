#include "tailcat/protocol.hpp"

#include <algorithm>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace tailcat {
namespace {

constexpr char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64url_encode(std::span<const std::uint8_t> in) {
  std::string out;
  out.reserve((in.size() * 4 + 2) / 3);
  std::uint32_t acc = 0;
  int bits = 0;
  for (auto b : in) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push_back(kB64[(acc >> bits) & 0x3f]);
    }
  }
  if (bits) out.push_back(kB64[(acc << (6 - bits)) & 0x3f]);
  return out;
}

std::vector<std::uint8_t> base64url_decode(std::string_view in) {
  std::array<std::int16_t, 256> table{};
  table.fill(-1);
  for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(kB64[i])] = static_cast<std::int16_t>(i);
  std::vector<std::uint8_t> out;
  out.reserve(in.size() * 3 / 4 + 2);
  std::uint32_t acc = 0;
  int bits = 0;
  for (char ch : in) {
    const auto v = table[static_cast<unsigned char>(ch)];
    if (v < 0) throw std::runtime_error("invalid base64url in tailcat address");
    acc = (acc << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xff));
    }
  }
  if (bits && (acc & ((1u << bits) - 1u)) != 0) throw std::runtime_error("non-zero base64url padding bits");
  return out;
}

void put_type_value(std::vector<std::uint8_t>& out, std::uint8_t major, std::uint64_t v) {
  if (v < 24) out.push_back(static_cast<std::uint8_t>((major << 5) | v));
  else if (v <= 0xff) { out.push_back(static_cast<std::uint8_t>((major << 5) | 24)); out.push_back(static_cast<std::uint8_t>(v)); }
  else if (v <= 0xffff) { out.push_back(static_cast<std::uint8_t>((major << 5) | 25)); out.push_back(static_cast<std::uint8_t>(v >> 8)); out.push_back(static_cast<std::uint8_t>(v)); }
  else if (v <= 0xffffffffULL) {
    out.push_back(static_cast<std::uint8_t>((major << 5) | 26));
    for (int s = 24; s >= 0; s -= 8) out.push_back(static_cast<std::uint8_t>(v >> s));
  } else {
    out.push_back(static_cast<std::uint8_t>((major << 5) | 27));
    for (int s = 56; s >= 0; s -= 8) out.push_back(static_cast<std::uint8_t>(v >> s));
  }
}

void put_int(std::vector<std::uint8_t>& out, std::int64_t v) {
  if (v >= 0) put_type_value(out, 0, static_cast<std::uint64_t>(v));
  else put_type_value(out, 1, static_cast<std::uint64_t>(-1 - v));
}
void put_text(std::vector<std::uint8_t>& out, std::string_view s) {
  put_type_value(out, 3, s.size()); out.insert(out.end(), s.begin(), s.end());
}
void put_bytes(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> b) {
  put_type_value(out, 2, b.size()); out.insert(out.end(), b.begin(), b.end());
}
void put_array(std::vector<std::uint8_t>& out, std::size_t n) { put_type_value(out, 4, n); }
void put_map(std::vector<std::uint8_t>& out, std::size_t n) { put_type_value(out, 5, n); }

class CborReader {
 public:
  explicit CborReader(std::span<const std::uint8_t> b) : b_(b) {}
  std::pair<std::uint8_t, std::uint64_t> head() {
    if (pos_ >= b_.size()) throw std::runtime_error("truncated CBOR");
    const auto x = b_[pos_++];
    const std::uint8_t major = x >> 5, ai = x & 31;
    std::uint64_t v = 0;
    if (ai < 24) v = ai;
    else if (ai == 24) v = take_uint(1);
    else if (ai == 25) v = take_uint(2);
    else if (ai == 26) v = take_uint(4);
    else if (ai == 27) v = take_uint(8);
    else throw std::runtime_error("unsupported indefinite/reserved CBOR item");
    return {major, v};
  }
  std::size_t map_len() { auto [m,n]=head(); if(m!=5) throw std::runtime_error("expected CBOR map"); return checked_size(n); }
  std::size_t array_len() { auto [m,n]=head(); if(m!=4) throw std::runtime_error("expected CBOR array"); return checked_size(n); }
  std::string text() {
    auto [m,n]=head(); if(m!=3) throw std::runtime_error("expected CBOR text"); auto sz=checked_size(n); require(sz);
    std::string s(reinterpret_cast<const char*>(b_.data()+pos_), sz); pos_+=sz; return s;
  }
  Key32 key32() {
    auto [m,n]=head(); if(m!=2 || n!=32) throw std::runtime_error("expected 32-byte CBOR byte string"); require(32);
    Key32 k{}; std::copy_n(b_.data()+pos_,32,k.data()); pos_+=32; return k;
  }
  std::int64_t integer() {
    auto [m,n]=head();
    if (n > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) throw std::runtime_error("CBOR integer overflow");
    if(m==0) return static_cast<std::int64_t>(n);
    if(m==1) return -1-static_cast<std::int64_t>(n);
    throw std::runtime_error("expected CBOR integer");
  }
  bool boolean() {
    if (pos_ >= b_.size()) throw std::runtime_error("truncated CBOR boolean");
    const auto x=b_[pos_++]; if(x==0xf4) return false; if(x==0xf5) return true; throw std::runtime_error("expected CBOR boolean");
  }
  void skip() {
    if (pos_ >= b_.size()) throw std::runtime_error("truncated CBOR");
    const auto initial=b_[pos_];
    if (initial==0xf4 || initial==0xf5 || initial==0xf6) { ++pos_; return; }
    auto [m,n]=head();
    switch(m) {
      case 0: case 1: return;
      case 2: case 3: require(checked_size(n)); pos_+=checked_size(n); return;
      case 4: for(std::uint64_t i=0;i<n;++i) skip(); return;
      case 5: for(std::uint64_t i=0;i<n;++i){ skip(); skip(); } return;
      default: throw std::runtime_error("unsupported CBOR item");
    }
  }
  bool done() const { return pos_==b_.size(); }
 private:
  std::uint64_t take_uint(std::size_t n) { require(n); std::uint64_t v=0; for(std::size_t i=0;i<n;++i) v=(v<<8)|b_[pos_++]; return v; }
  std::size_t checked_size(std::uint64_t n) const { if(n>std::numeric_limits<std::size_t>::max()) throw std::runtime_error("CBOR length overflow"); return static_cast<std::size_t>(n); }
  void require(std::size_t n) const { if(n>b_.size()-pos_) throw std::runtime_error("truncated CBOR payload"); }
  std::span<const std::uint8_t> b_; std::size_t pos_=0;
};

std::size_t node_fields(const DerpNode& n) {
  return (!n.name.empty()) + (n.region_id!=0) + (!n.host_name.empty()) + (!n.cert_name.empty()) + (!n.ipv4.empty()) + (!n.ipv6.empty()) + (n.stun_port!=0) + (n.derp_port!=0) + n.insecure_for_tests;
}
void encode_node(std::vector<std::uint8_t>& out, const DerpNode& n) {
  put_map(out,node_fields(n));
  if(!n.name.empty()){put_text(out,"n");put_text(out,n.name);} if(n.region_id){put_text(out,"i");put_int(out,n.region_id);}
  if(!n.host_name.empty()){put_text(out,"h");put_text(out,n.host_name);} if(!n.cert_name.empty()){put_text(out,"t");put_text(out,n.cert_name);}
  if(!n.ipv4.empty()){put_text(out,"4");put_text(out,n.ipv4);} if(!n.ipv6.empty()){put_text(out,"6");put_text(out,n.ipv6);}
  if(n.stun_port){put_text(out,"s");put_int(out,n.stun_port);} if(n.derp_port){put_text(out,"d");put_int(out,n.derp_port);}
  if(n.insecure_for_tests){put_text(out,"x");out.push_back(0xf5);}
}
DerpNode decode_node(CborReader& r) {
  DerpNode n; for(std::size_t i=0, count=r.map_len(); i<count; ++i){auto k=r.text();
    if(k=="n")n.name=r.text(); else if(k=="i")n.region_id=r.integer(); else if(k=="h")n.host_name=r.text(); else if(k=="t")n.cert_name=r.text();
    else if(k=="4")n.ipv4=r.text(); else if(k=="6")n.ipv6=r.text(); else if(k=="s")n.stun_port=r.integer(); else if(k=="d")n.derp_port=r.integer();
    else if(k=="x")n.insecure_for_tests=r.boolean(); else r.skip(); }
  return n;
}
void encode_region(std::vector<std::uint8_t>& out, const DerpRegion& reg) {
  const std::size_t fields=(reg.region_id!=0)+(!reg.region_code.empty())+(!reg.region_name.empty())+(!reg.nodes.empty()); put_map(out,fields);
  if(reg.region_id){put_text(out,"i");put_int(out,reg.region_id);} if(!reg.region_code.empty()){put_text(out,"c");put_text(out,reg.region_code);}
  if(!reg.region_name.empty()){put_text(out,"m");put_text(out,reg.region_name);} if(!reg.nodes.empty()){put_text(out,"N");put_array(out,reg.nodes.size());for(auto& n:reg.nodes)encode_node(out,n);}
}
DerpRegion decode_region(CborReader& r) {
  DerpRegion reg; for(std::size_t i=0,count=r.map_len();i<count;++i){auto k=r.text();
    if(k=="i")reg.region_id=r.integer(); else if(k=="c")reg.region_code=r.text(); else if(k=="m")reg.region_name=r.text();
    else if(k=="N"){auto n=r.array_len();reg.nodes.reserve(n);for(std::size_t j=0;j<n;++j)reg.nodes.push_back(decode_node(r));} else r.skip(); }
  return reg;
}

} // namespace

std::string encode_tailcat_addr(const ConnInfo& info) {
  std::vector<std::uint8_t> b; std::size_t fields=1+info.server_disco_public.has_value()+info.preshared_key.has_value()+(!info.regions.empty())+(info.region_id!=0); put_map(b,fields);
  put_text(b,"p");put_bytes(b,info.server_public);
  if(info.server_disco_public){put_text(b,"k");put_bytes(b,*info.server_disco_public);} if(info.preshared_key){put_text(b,"q");put_bytes(b,*info.preshared_key);}
  if(!info.regions.empty()){put_text(b,"r");put_array(b,info.regions.size());for(auto& reg:info.regions)encode_region(b,reg);} if(info.region_id){put_text(b,"i");put_int(b,info.region_id);}
  return "tc"+base64url_encode(b);
}

ConnInfo decode_tailcat_addr(std::string_view addr) {
  if(!addr.starts_with("tc") || addr.size()<=2) throw std::runtime_error("tailcat address must start with tc");
  auto bytes=base64url_decode(addr.substr(2)); CborReader r(bytes); ConnInfo info; bool have_pub=false;
  for(std::size_t i=0,count=r.map_len();i<count;++i){auto k=r.text();
    if(k=="p"){info.server_public=r.key32();have_pub=true;} else if(k=="k")info.server_disco_public=r.key32(); else if(k=="q")info.preshared_key=r.key32();
    else if(k=="r"){auto n=r.array_len();info.regions.reserve(n);for(std::size_t j=0;j<n;++j)info.regions.push_back(decode_region(r));} else if(k=="i")info.region_id=r.integer(); else r.skip(); }
  if (!have_pub) throw std::runtime_error("tailcat address missing server public key");
  if (!r.done()) throw std::runtime_error("trailing CBOR data in tailcat address");
  return info;
}

std::array<std::uint8_t,16> tailcat_ip_for_key(const Key32& key) {
  std::array<std::uint8_t,16> a{}; a[0]=0xfd;a[1]=0x7a;a[2]=0x11;a[3]=0x5c;a[4]=0xa1;a[5]=0xe0;std::copy_n(key.begin(),10,a.begin()+6);return a;
}
std::string format_ipv6(const std::array<std::uint8_t,16>& a) {
  std::ostringstream o; o<<std::hex; for(int i=0;i<8;++i){if(i)o<<':'<<std::noshowbase;o<<((static_cast<unsigned>(a[2*i])<<8)|a[2*i+1]);} return o.str();
}

std::vector<std::uint8_t> encode_meow_ping(const Key32& node_key,const Key32& disco_key){std::vector<std::uint8_t>b={'m','e','o','w',1};b.insert(b.end(),node_key.begin(),node_key.end());b.insert(b.end(),disco_key.begin(),disco_key.end());return b;}
std::vector<std::uint8_t> encode_meowed(){return {'m','e','o','w',2};}
bool is_meow_packet(std::span<const std::uint8_t> p){return p.size()>=4&&p[0]=='m'&&p[1]=='e'&&p[2]=='o'&&p[3]=='w';}
bool is_meowed_packet(std::span<const std::uint8_t> p){return p.size()>=5&&is_meow_packet(p)&&p[4]==2;}
bool parse_meow_ping(std::span<const std::uint8_t> p,Key32& n,Key32& d){if(p.size()<69||!is_meow_packet(p)||p[4]!=1)return false;std::copy_n(p.begin()+5,32,n.begin());std::copy_n(p.begin()+37,32,d.begin());return std::any_of(d.begin(),d.end(),[](auto x){return x!=0;});}

std::array<std::uint8_t,5> encode_derp_frame_header(DerpFrameType t,std::uint32_t len){return {static_cast<std::uint8_t>(t),static_cast<std::uint8_t>(len>>24),static_cast<std::uint8_t>(len>>16),static_cast<std::uint8_t>(len>>8),static_cast<std::uint8_t>(len)};}
DerpFrameHeader decode_derp_frame_header(std::span<const std::uint8_t>b){if(b.size()<5)throw std::runtime_error("short DERP frame header");return {static_cast<DerpFrameType>(b[0]),(static_cast<std::uint32_t>(b[1])<<24)|(static_cast<std::uint32_t>(b[2])<<16)|(static_cast<std::uint32_t>(b[3])<<8)|b[4]};}

} // namespace tailcat
