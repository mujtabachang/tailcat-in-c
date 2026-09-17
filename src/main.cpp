#include "tailcat/address.hpp"
#include "tailcat/crypto.hpp"
#include "tailcat/derp.hpp"
#include "tailcat/session.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace tailcat;
namespace {
constexpr std::string_view kDefaultMap = "https://tailcat.dev/derpmap.json";
std::atomic<bool> g_stop{false};
void on_signal(int){g_stop=true;}

[[noreturn]] void usage(int code=2){
  std::ostream& o=code?std::cerr:std::cout;
  o << "tailcat (C++ rewrite)\n\n"
       "Usage:\n"
       "  tailcat                         serve stdin/stdout\n"
       "  tailcat <tc-address> [port]     connect stdin/stdout or TCP port\n"
       "  tailcat serve <ports|all|exit-node>\n"
       "  tailcat forward [--bind=ADDR] <tc-address> <local:remote>...\n"
       "  tailcat browse <tc-address>\n"
       "  tailcat ping <tc-address>\n"
       "  tailcat parse <tc-address>\n"
       "  tailcat --version\n";
  std::exit(code);
}

std::vector<std::uint16_t> parse_ports(const std::string&s){std::vector<std::uint16_t>out;std::size_t p=0;while(p<s.size()){auto c=s.find(',',p);auto part=s.substr(p,c==std::string::npos?std::string::npos:c-p);int n=std::stoi(part);if(n<1||n>65535)throw Error("invalid port: "+part);out.push_back(static_cast<std::uint16_t>(n));if(c==std::string::npos)break;p=c+1;}return out;}

void run_server(ServerOptions options){
  auto sel=fetch_derp_selection(kDefaultMap,"server"); auto kp=make_keypair();auto psk=random_key32();ConnInfo ci;ci.server_public=kp.public_key;ci.preshared_key=psk;ci.region_id=sel.region_id;ci.nodes=sel.nodes;
  std::cerr << "# Selected bootstrap relay region " << sel.region_id << ", " << sel.nodes.front().host_name << "\n";
  std::cerr << "# 🐈 Server listening with new address: " << encode_address(ci) << "\n";
  ServerSession server(kp,psk,sel.nodes.front(),std::move(options));server.run();
}

void pipe_stream(std::shared_ptr<Stream> s){
  std::thread reader([s]{try{for(;;){auto b=s->read();if(b.empty())break;std::cout.write(reinterpret_cast<const char*>(b.data()),b.size());std::cout.flush();}}catch(const std::exception&e){std::cerr<<"tailcat: "<<e.what()<<"\n";}});
  try{std::array<std::uint8_t,32768>b{};while(std::cin){std::cin.read(reinterpret_cast<char*>(b.data()),b.size());auto n=std::cin.gcount();if(n<=0)break;s->write(std::span<const std::uint8_t>(b.data(),static_cast<std::size_t>(n)));}}catch(const std::exception&e){std::cerr<<"tailcat: "<<e.what()<<"\n";}s->close();if(reader.joinable())reader.join();
}

struct Mapping{std::uint16_t local=0;std::string host="127.0.0.1";std::uint16_t remote=0;};
Mapping parse_mapping(const std::string&s){
  std::vector<std::string>parts;std::size_t p=0;while(true){auto c=s.find(':',p);parts.push_back(s.substr(p,c==std::string::npos?std::string::npos:c-p));if(c==std::string::npos)break;p=c+1;}
  Mapping m;if(parts.size()==1){m.local=m.remote=static_cast<std::uint16_t>(std::stoi(parts[0]));}else if(parts.size()==2){m.local=static_cast<std::uint16_t>(std::stoi(parts[0]));m.remote=static_cast<std::uint16_t>(std::stoi(parts[1]));}else if(parts.size()==3){m.local=static_cast<std::uint16_t>(std::stoi(parts[0]));m.host=parts[1];m.remote=static_cast<std::uint16_t>(std::stoi(parts[2]));}else throw Error("invalid forward mapping: "+s);return m;
}

void bridge_socket(std::shared_ptr<boost::asio::ip::tcp::socket> sock,std::shared_ptr<Stream> stream){
  auto a=std::thread([sock,stream]{try{std::array<std::uint8_t,32768>b{};for(;;){auto n=sock->read_some(boost::asio::buffer(b));if(!n)break;stream->write(std::span<const std::uint8_t>(b.data(),n));}}catch(...){}try{stream->close();}catch(...) {}});
  auto b=std::thread([sock,stream]{try{for(;;){auto d=stream->read();if(d.empty())break;boost::asio::write(*sock,boost::asio::buffer(d));}}catch(...){}boost::system::error_code ec;sock->close(ec);});a.detach();b.detach();
}

void run_forward(const ConnInfo&ci,std::string bind,std::vector<Mapping> maps,bool open_browser){
  auto client=std::make_shared<ClientSession>(ci,make_keypair());client->connect();auto io=std::make_shared<boost::asio::io_context>();std::vector<std::shared_ptr<boost::asio::ip::tcp::acceptor>>acceptors;
  for(auto m:maps){auto acc=std::make_shared<boost::asio::ip::tcp::acceptor>(*io);auto addr=boost::asio::ip::make_address(bind);acc->open(boost::asio::ip::tcp::v4());acc->set_option(boost::asio::socket_base::reuse_address(true));acc->bind({addr,m.local});acc->listen();auto port=acc->local_endpoint().port();std::cerr<<"# forwarding "<<bind<<":"<<port<<" -> "<<m.host<<":"<<m.remote<<"\n";if(open_browser){std::string url="http://127.0.0.1:"+std::to_string(port)+"/";
#ifdef _WIN32
    std::system(("start \"\" \""+url+"\"").c_str());
#elif __APPLE__
    std::system(("open \""+url+"\" >/dev/null 2>&1 &").c_str());
#else
    std::system(("xdg-open \""+url+"\" >/dev/null 2>&1 &").c_str());
#endif
  }
  acceptors.push_back(acc);std::thread([acc,client,m]{while(!g_stop){try{auto sock=std::make_shared<boost::asio::ip::tcp::socket>(acc->get_executor());acc->accept(*sock);auto st=client->open("tcp:"+m.host+":"+std::to_string(m.remote));bridge_socket(sock,st);}catch(...){if(g_stop)break;}}}).detach();}
  while(!g_stop)std::this_thread::sleep_for(std::chrono::milliseconds(200));for(auto&a:acceptors){boost::system::error_code ec;a->close(ec);}client->close();
}

ConnInfo resolved_info(const std::string& addr){auto ci=parse_address(addr);if(ci.nodes.empty()&&ci.region_id){auto s=fetch_derp_selection(kDefaultMap,"client",ci.region_id);ci.nodes=s.nodes;}return ci;}
}

int main(int argc,char**argv){
  try{crypto_init();std::signal(SIGINT,on_signal);std::signal(SIGTERM,on_signal);std::vector<std::string>a(argv+1,argv+argc);if(!a.empty()&&(a[0]=="--help"||a[0]=="-h"))usage(0);if(!a.empty()&&a[0]=="--version"){std::cout<<"tailcat-cpp 0.1.0\n";return 0;}
    if(a.empty()){ServerOptions o;o.stdio=true;run_server(o);return 0;}
    if(a[0]=="parse"){if(a.size()!=2)usage();std::cout<<address_to_json(parse_address(a[1]));return 0;}
    if(a[0]=="ping"){if(a.size()!=2)usage();ClientSession c(resolved_info(a[1]),make_keypair());c.connect();std::cout<<"meowed in "<<c.ping()<<" ms\n";return 0;}
    if(a[0]=="serve"){if(a.size()!=2)usage();ServerOptions o;if(a[1]=="all")o.allow_all_local_ports=true;else if(a[1]=="exit-node")o.exit_node=true;else for(auto p:parse_ports(a[1]))o.allowed_local_ports.insert(p);run_server(o);return 0;}
    if(a[0]=="forward"){std::string bind="127.0.0.1";std::size_t i=1;if(i<a.size()&&a[i].starts_with("--bind=")){bind=a[i].substr(7);++i;}if(i>=a.size())usage();auto ci=resolved_info(a[i++]);std::vector<Mapping>m;for(;i<a.size();++i)m.push_back(parse_mapping(a[i]));if(m.empty())usage();run_forward(ci,bind,m,false);return 0;}
    if(a[0]=="browse"){if(a.size()!=2)usage();run_forward(resolved_info(a[1]),"127.0.0.1",{{0,"127.0.0.1",80}},true);return 0;}
    if(a[0].starts_with("tc")){auto ci=resolved_info(a[0]);ClientSession c(ci,make_keypair());c.connect();auto target=a.size()>1?"tcp:127.0.0.1:"+a[1]:"stdio";pipe_stream(c.open(target));return 0;}
    usage();
  }catch(const std::exception&e){std::cerr<<"tailcat: "<<e.what()<<"\n";return 1;}
}
