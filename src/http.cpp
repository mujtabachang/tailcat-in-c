#include "tailcat/http.hpp"
#include "tailcat/common.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <algorithm>
#include <cctype>
#include <sstream>

namespace tailcat {
namespace {
struct ParsedUrl { std::string host; std::string port; std::string target; };
ParsedUrl parse_https(std::string_view url) {
  constexpr std::string_view p="https://"; if(!url.starts_with(p))throw Error("only https:// URLs are supported");
  auto rest=url.substr(p.size()); auto slash=rest.find('/'); std::string authority(rest.substr(0,slash)); std::string target=slash==std::string_view::npos?"/":std::string(rest.substr(slash));
  std::string host=authority,port="443"; auto colon=authority.rfind(':'); if(colon!=std::string::npos&&authority.find(':')==colon){host=authority.substr(0,colon);port=authority.substr(colon+1);} return {host,port,target};
}
std::string trim(std::string s){while(!s.empty()&&std::isspace(static_cast<unsigned char>(s.front())))s.erase(s.begin());while(!s.empty()&&std::isspace(static_cast<unsigned char>(s.back())))s.pop_back();return s;}
}

HttpResponse https_get(std::string_view url,const std::map<std::string,std::string>& headers){
  auto u=parse_https(url); boost::asio::io_context io; boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_client); ctx.set_default_verify_paths();
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> s(io,ctx); s.set_verify_mode(boost::asio::ssl::verify_peer); s.set_verify_callback(boost::asio::ssl::host_name_verification(u.host));
  SSL_set_tlsext_host_name(s.native_handle(),u.host.c_str()); boost::asio::ip::tcp::resolver r(io); boost::asio::connect(s.next_layer(),r.resolve(u.host,u.port)); s.handshake(boost::asio::ssl::stream_base::client);
  std::ostringstream req; req<<"GET "<<u.target<<" HTTP/1.1\r\nHost: "<<u.host<<"\r\nUser-Agent: tailcat-cpp/0.1\r\nAccept: application/json\r\nConnection: close\r\n"; for(auto&[k,v]:headers)req<<k<<": "<<v<<"\r\n"; req<<"\r\n"; auto q=req.str(); boost::asio::write(s,boost::asio::buffer(q));
  boost::asio::streambuf buf; boost::asio::read_until(s,buf,"\r\n\r\n"); std::istream in(&buf); std::string line; std::getline(in,line); if(!line.empty()&&line.back()=='\r')line.pop_back(); std::istringstream sl(line); std::string http; HttpResponse res; sl>>http>>res.status;
  while(std::getline(in,line)&&line!="\r"){if(!line.empty()&&line.back()=='\r')line.pop_back();auto c=line.find(':');if(c!=std::string::npos)res.headers.emplace(line.substr(0,c),trim(line.substr(c+1)));}
  std::ostringstream body; if(buf.size())body<<&buf; boost::system::error_code ec; for(;;){std::array<char,8192>b{};auto n=s.read_some(boost::asio::buffer(b),ec);if(n)body.write(b.data(),n);if(ec)break;} res.body=body.str(); return res;
}

}  // namespace tailcat
