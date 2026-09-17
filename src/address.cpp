#include "tailcat/address.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>

namespace tailcat {
namespace {

void cbor_uint(std::vector<std::uint8_t>& out, std::uint8_t major, std::uint64_t value) {
  if (value < 24) out.push_back(static_cast<std::uint8_t>((major << 5) | value));
  else if (value <= 0xff) { out.push_back(static_cast<std::uint8_t>((major << 5) | 24)); out.push_back(value); }
  else if (value <= 0xffff) { out.push_back(static_cast<std::uint8_t>((major << 5) | 25)); append_be16(out, value); }
  else if (value <= 0xffffffffULL) { out.push_back(static_cast<std::uint8_t>((major << 5) | 26)); append_be32(out, value); }
  else {
    out.push_back(static_cast<std::uint8_t>((major << 5) | 27));
    for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
  }
}
void cbor_text(std::vector<std::uint8_t>& out, std::string_view s) {
  cbor_uint(out, 3, s.size()); out.insert(out.end(), s.begin(), s.end());
}
void cbor_bytes(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> b) {
  cbor_uint(out, 2, b.size()); out.insert(out.end(), b.begin(), b.end());
}
void cbor_bool(std::vector<std::uint8_t>& out, bool v) { out.push_back(v ? 0xf5 : 0xf4); }

class Reader {
 public:
  explicit Reader(std::span<const std::uint8_t> b) : b_(b) {}
  bool empty() const { return pos_ == b_.size(); }
  std::pair<std::uint8_t, std::uint64_t> head() {
    if (pos_ >= b_.size()) throw Error("truncated CBOR");
    std::uint8_t c = b_[pos_++], ai = c & 31, major = c >> 5;
    std::uint64_t v = 0;
    if (ai < 24) v = ai;
    else if (ai == 24) v = take();
    else if (ai == 25) { v = std::uint64_t(take()) << 8; v |= take(); }
    else if (ai == 26) { for (int i=0;i<4;++i) v=(v<<8)|take(); }
    else if (ai == 27) { for (int i=0;i<8;++i) v=(v<<8)|take(); }
    else throw Error("indefinite CBOR values are unsupported");
    return {major, v};
  }
  std::string text() {
    auto [m,n]=head(); if(m!=3) throw Error("expected CBOR text");
    if (n > b_.size()-pos_) throw Error("truncated CBOR text");
    std::string s(reinterpret_cast<const char*>(b_.data()+pos_), static_cast<std::size_t>(n)); pos_ += n; return s;
  }
  std::vector<std::uint8_t> bytes() {
    auto [m,n]=head(); if(m!=2) throw Error("expected CBOR bytes");
    if (n > b_.size()-pos_) throw Error("truncated CBOR bytes");
    std::vector<std::uint8_t> v(b_.begin()+pos_, b_.begin()+pos_+n); pos_ += n; return v;
  }
  std::int64_t integer() {
    auto [m,n]=head();
    if(m==0) return static_cast<std::int64_t>(n);
    if(m==1) return -1-static_cast<std::int64_t>(n);
    throw Error("expected CBOR integer");
  }
  bool boolean() {
    if(pos_>=b_.size()) throw Error("truncated CBOR bool");
    if(b_[pos_]==0xf4){++pos_;return false;} if(b_[pos_]==0xf5){++pos_;return true;}
    throw Error("expected CBOR bool");
  }
  std::uint64_t array_len(){auto [m,n]=head();if(m!=4)throw Error("expected CBOR array");return n;}
  std::uint64_t map_len(){auto [m,n]=head();if(m!=5)throw Error("expected CBOR map");return n;}
  void skip() {
    if (pos_ >= b_.size()) throw Error("truncated CBOR");
    std::uint8_t c=b_[pos_], major=c>>5;
    if (c==0xf4||c==0xf5||c==0xf6){++pos_;return;}
    auto [m,n]=head(); (void)m;
    if(major==2||major==3){ if(n>b_.size()-pos_)throw Error("truncated CBOR"); pos_+=n; }
    else if(major==4){for(std::uint64_t i=0;i<n;++i)skip();}
    else if(major==5){for(std::uint64_t i=0;i<n;++i){skip();skip();}}
    else if(major>1) throw Error("unsupported CBOR type");
  }
 private:
  std::uint8_t take(){if(pos_>=b_.size())throw Error("truncated CBOR");return b_[pos_++];}
  std::span<const std::uint8_t> b_; std::size_t pos_=0;
};

void put_node(std::vector<std::uint8_t>& out, const DerpNode& n) {
  std::uint64_t fields = 0;
  fields += !n.name.empty(); fields += !n.host_name.empty(); fields += !n.cert_name.empty();
  fields += !n.ipv4.empty(); fields += !n.ipv6.empty(); fields += n.derp_port != 0 && n.derp_port != 443;
  fields += n.insecure_for_tests;
  cbor_uint(out,5,fields);
  if(!n.name.empty()){cbor_text(out,"n");cbor_text(out,n.name);} if(!n.host_name.empty()){cbor_text(out,"h");cbor_text(out,n.host_name);}
  if(!n.cert_name.empty()){cbor_text(out,"t");cbor_text(out,n.cert_name);} if(!n.ipv4.empty()){cbor_text(out,"4");cbor_text(out,n.ipv4);}
  if(!n.ipv6.empty()){cbor_text(out,"6");cbor_text(out,n.ipv6);} if(n.derp_port!=0&&n.derp_port!=443){cbor_text(out,"d");cbor_uint(out,0,n.derp_port);}
  if(n.insecure_for_tests){cbor_text(out,"x");cbor_bool(out,true);}
}

DerpNode read_node(Reader& r) {
  DerpNode n; const auto fields=r.map_len();
  for(std::uint64_t i=0;i<fields;++i){auto k=r.text(); if(k=="n")n.name=r.text(); else if(k=="h")n.host_name=r.text(); else if(k=="t")n.cert_name=r.text();
    else if(k=="4")n.ipv4=r.text(); else if(k=="6")n.ipv6=r.text(); else if(k=="d")n.derp_port=static_cast<std::uint16_t>(r.integer()); else if(k=="x")n.insecure_for_tests=r.boolean(); else r.skip();}
  if(n.derp_port==0)n.derp_port=443; if(n.name.empty())n.name=n.host_name; return n;
}

}  // namespace

std::string base64url_encode(std::span<const std::uint8_t> input) {
  if(input.empty()) return {};
  std::string out(((input.size()+2)/3)*4, '\0');
  int n=EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), input.data(), input.size()); out.resize(n);
  for(char& c:out){if(c=='+')c='-';else if(c=='/')c='_';}
  while(!out.empty()&&out.back()=='=')out.pop_back(); return out;
}
std::vector<std::uint8_t> base64url_decode(std::string_view input) {
  std::string s(input); for(char& c:s){if(c=='-')c='+';else if(c=='_')c='/';}
  while(s.size()%4)s.push_back('='); std::vector<std::uint8_t> out((s.size()/4)*3);
  int n=EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(s.data()), s.size()); if(n<0)throw Error("invalid base64url");
  std::size_t padding=0; if(!s.empty()&&s.back()=='=')padding++; if(s.size()>1&&s[s.size()-2]=='=')padding++; out.resize(static_cast<std::size_t>(n)-padding); return out;
}

std::string encode_address(const ConnInfo& info) {
  std::vector<std::uint8_t> cbor;
  std::uint64_t fields=2; if(info.region_id!=0)fields++; if(!info.nodes.empty())fields++;
  cbor_uint(cbor,5,fields); cbor_text(cbor,"p"); cbor_bytes(cbor,info.server_public); cbor_text(cbor,"q"); cbor_bytes(cbor,info.preshared_key);
  if(info.region_id!=0){cbor_text(cbor,"i"); if(info.region_id>=0)cbor_uint(cbor,0,info.region_id); else cbor_uint(cbor,1,-1-info.region_id);}
  if(!info.nodes.empty()){
    cbor_text(cbor,"r"); cbor_uint(cbor,4,1); cbor_uint(cbor,5,1); cbor_text(cbor,"N"); cbor_uint(cbor,4,info.nodes.size()); for(const auto& n:info.nodes)put_node(cbor,n);
  }
  return "tc"+base64url_encode(cbor);
}

ConnInfo parse_address(std::string_view address) {
  if(!address.starts_with("tc"))throw Error("tailcat address doesn't start with \"tc\"");
  auto raw=base64url_decode(address.substr(2)); Reader r(raw); ConnInfo info; bool have_pub=false;
  const auto fields=r.map_len();
  for(std::uint64_t i=0;i<fields;++i){auto k=r.text(); if(k=="p"){auto b=r.bytes();if(b.size()!=32)throw Error("invalid server key length");std::copy(b.begin(),b.end(),info.server_public.begin());have_pub=true;}
    else if(k=="q"){auto b=r.bytes();if(b.size()!=32)throw Error("invalid preshared key length");std::copy(b.begin(),b.end(),info.preshared_key.begin());}
    else if(k=="i")info.region_id=r.integer();
    else if(k=="k")r.skip();
    else if(k=="r"){
      const auto regs=r.array_len(); for(std::uint64_t ri=0;ri<regs;++ri){const auto rf=r.map_len(); for(std::uint64_t f=0;f<rf;++f){auto rk=r.text(); if(rk=="N"){auto nn=r.array_len(); for(std::uint64_t j=0;j<nn;++j)info.nodes.push_back(read_node(r));} else r.skip();}}
    } else r.skip();}
  if(!have_pub)throw Error("tailcat address missing server public key"); return info;
}

std::string address_to_json(const ConnInfo& info) {
  std::ostringstream o; o << "{\n  \"ServerPublic\": \"" << hex(info.server_public) << "\",\n  \"PresharedKey\": \"" << hex(info.preshared_key) << "\",\n  \"RegionID\": " << info.region_id << ",\n  \"Nodes\": [";
  for(std::size_t i=0;i<info.nodes.size();++i){const auto& n=info.nodes[i]; if(i)o<<","; o << "\n    {\"HostName\":\""<<n.host_name<<"\",\"DERPPort\":"<<n.derp_port<<"}";}
  if(!info.nodes.empty())o<<"\n  "; o << "]\n}\n"; return o.str();
}

}  // namespace tailcat
