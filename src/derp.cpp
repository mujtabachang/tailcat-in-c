#include "tailcat/derp.hpp"
#include "tailcat/http.hpp"

#include <boost/json.hpp>
#include <boost/json/src.hpp>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>

namespace tailcat {
namespace {
constexpr std::uint8_t kServerKey=0x01,kClientInfo=0x02,kServerInfo=0x03,kSend=0x04,kRecv=0x05,kKeepAlive=0x06,kPeerGone=0x08,kPeerPresent=0x09,kPing=0x12,kPong=0x13,kHealth=0x14,kRestarting=0x15;
constexpr std::string_view kMagic="DERP\xF0\x9F\x94\x91";
std::string port_string(std::uint16_t p){return std::to_string(p?p:443);}
std::string get_string(const boost::json::object& o,std::string_view k){if(auto*p=o.if_contains(k);p&&p->is_string())return std::string(p->as_string());return {};}
std::int64_t get_int(const boost::json::object& o,std::string_view k,std::int64_t d=0){if(auto*p=o.if_contains(k);p&&p->is_int64())return p->as_int64();if(auto*p=o.if_contains(k);p&&p->is_uint64())return static_cast<std::int64_t>(p->as_uint64());return d;}
bool get_bool(const boost::json::object&o,std::string_view k){if(auto*p=o.if_contains(k);p&&p->is_bool())return p->as_bool();return false;}
}

DerpClient::DerpClient(KeyPair kp,DerpNode node):keypair_(kp),node_(std::move(node)),ssl_ctx_(boost::asio::ssl::context::tls_client){crypto_init();ssl_ctx_.set_default_verify_paths();}
DerpClient::~DerpClient(){close();}

void DerpClient::connect(){
  if(connected_)return; boost::asio::ip::tcp::resolver resolver(io_); stream_=std::make_unique<SslStream>(io_,ssl_ctx_);
  if(node_.insecure_for_tests)stream_->set_verify_mode(boost::asio::ssl::verify_none); else {stream_->set_verify_mode(boost::asio::ssl::verify_peer);stream_->set_verify_callback(boost::asio::ssl::host_name_verification(node_.cert_name.empty()?node_.host_name:node_.cert_name));}
  SSL_set_tlsext_host_name(stream_->native_handle(),node_.host_name.c_str()); boost::asio::connect(stream_->next_layer(),resolver.resolve(node_.host_name,port_string(node_.derp_port))); stream_->handshake(boost::asio::ssl::stream_base::client);
  std::ostringstream req;req<<"GET /derp HTTP/1.1\r\nHost: "<<node_.host_name<<"\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nUser-Agent: tailcat-cpp/0.1\r\n\r\n";auto q=req.str();boost::asio::write(*stream_,boost::asio::buffer(q));
  boost::asio::streambuf hdr;boost::asio::read_until(*stream_,hdr,"\r\n\r\n");std::istream hi(&hdr);std::string status;std::getline(hi,status);if(status.find(" 101 ")==std::string::npos)throw Error("DERP HTTP upgrade failed: "+status);
  auto [t,greeting]=read_frame();if(t!=kServerKey||greeting.size()<40||std::string_view(reinterpret_cast<char*>(greeting.data()),8)!=kMagic)throw Error("invalid DERP server greeting");std::copy(greeting.begin()+8,greeting.begin()+40,server_key_.begin());
  std::string json="{\"version\":2,\"CanAckPings\":true,\"AppName\":\"tailcat-cpp\"}"; auto boxed=nacl_box_seal(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(json.data()),json.size()),server_key_,keypair_.private_key); std::vector<std::uint8_t> ci;ci.insert(ci.end(),keypair_.public_key.begin(),keypair_.public_key.end());ci.insert(ci.end(),boxed.begin(),boxed.end());write_frame(kClientInfo,ci);
  for(;;){auto [ft,p]=read_frame();if(ft==kServerInfo){handle_server_info(p);break;}if(ft==kPing)write_frame(kPong,p);}
  connected_=true;
}
void DerpClient::handle_server_info(std::span<const std::uint8_t> p){(void)nacl_box_open(p,server_key_,keypair_.private_key);}
void DerpClient::close(){if(!stream_)return;boost::system::error_code ec;stream_->next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both,ec);stream_->next_layer().close(ec);stream_.reset();connected_=false;}
void DerpClient::write_raw(std::span<const std::uint8_t> b){boost::asio::write(*stream_,boost::asio::buffer(b.data(),b.size()));}
void DerpClient::read_exact(std::span<std::uint8_t> b){boost::asio::read(*stream_,boost::asio::buffer(b.data(),b.size()));}
void DerpClient::write_frame(std::uint8_t type,std::span<const std::uint8_t> payload){std::lock_guard lk(write_mu_);std::vector<std::uint8_t> h;h.push_back(type);append_be32(h,payload.size());write_raw(h);if(!payload.empty())write_raw(payload);}
std::pair<std::uint8_t,std::vector<std::uint8_t>> DerpClient::read_frame(){std::array<std::uint8_t,5>h{};read_exact(h);auto n=read_be32(h.data()+1);if(n>(1u<<20))throw Error("oversized DERP frame");std::vector<std::uint8_t>p(n);if(n)read_exact(p);return{h[0],std::move(p)};}
void DerpClient::send_to(const Key32& dst,std::span<const std::uint8_t> payload){if(payload.size()>65536)throw Error("DERP packet too large");std::vector<std::uint8_t>p; p.insert(p.end(),dst.begin(),dst.end());p.insert(p.end(),payload.begin(),payload.end());write_frame(kSend,p);}
DerpPacket DerpClient::receive(){
  for(;;){auto [t,p]=read_frame();if(t==kRecv){if(p.size()<32)continue;DerpPacket d;std::copy(p.begin(),p.begin()+32,d.source.begin());d.payload.assign(p.begin()+32,p.end());return d;}if(t==kPing){write_frame(kPong,p);continue;}if(t==kKeepAlive||t==kPeerGone||t==kPeerPresent)continue;if(t==kHealth){if(!p.empty())throw Error("DERP health error: "+std::string(p.begin(),p.end()));continue;}if(t==kRestarting)throw Error("DERP server restarting");}
}

DerpMapSelection fetch_derp_selection(std::string_view map_url,std::string_view mode,std::optional<std::int64_t>wanted){
  auto res=https_get(map_url,{{"Tailcat-Mode",std::string(mode)}});if(res.status!=200)throw Error("DERP map HTTP status "+std::to_string(res.status));boost::json::error_code ec;auto root=boost::json::parse(res.body,ec);if(ec||!root.is_object())throw Error("invalid DERP map JSON");auto&ro=root.as_object();auto*rv=ro.if_contains("Regions");if(!rv||!rv->is_object())throw Error("DERP map has no Regions");
  DerpMapSelection sel;for(auto&kv:rv->as_object()){if(!kv.value().is_object())continue;auto&reg=kv.value().as_object();std::int64_t rid=get_int(reg,"RegionID");if(!rid){try{rid=std::stoll(std::string(kv.key()));}catch(...){continue;}}if(wanted&&rid!=*wanted)continue;auto*nv=reg.if_contains("Nodes");if(!nv||!nv->is_array())continue;std::vector<DerpNode>nodes;for(auto&x:nv->as_array()){if(!x.is_object())continue;auto&o=x.as_object();if(get_bool(o,"STUNOnly"))continue;DerpNode n;n.name=get_string(o,"Name");n.host_name=get_string(o,"HostName");n.cert_name=get_string(o,"CertName");n.ipv4=get_string(o,"IPv4");n.ipv6=get_string(o,"IPv6");auto dp=get_int(o,"DERPPort",443);n.derp_port=static_cast<std::uint16_t>(dp?dp:443);n.insecure_for_tests=get_bool(o,"InsecureForTests");if(!n.host_name.empty())nodes.push_back(std::move(n));if(nodes.size()==2)break;}if(nodes.empty())continue;sel.region_id=rid;sel.nodes=std::move(nodes);return sel;}throw Error(wanted?"requested DERP region not found":"DERP map contains no usable regions");
}

} // namespace tailcat
