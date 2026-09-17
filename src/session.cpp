#include "tailcat/session.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>

#include <chrono>
#include <iostream>
#include <sstream>

namespace tailcat {
namespace {
std::pair<std::string,std::uint16_t> parse_host_port(std::string_view s){
  auto p=s.rfind(':');if(p==std::string_view::npos)throw Error("target must be host:port");auto host=std::string(s.substr(0,p));int port=std::stoi(std::string(s.substr(p+1)));if(port<1||port>65535)throw Error("invalid TCP port");return{host,static_cast<std::uint16_t>(port)};
}
std::uint64_t now_nonce(){return static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());}
std::string u64_text(std::uint64_t v){return std::to_string(v);}
}

Stream::Stream(ClientSession*o,std::uint32_t id):owner_(o),id_(id){}
Stream::~Stream(){try{close();}catch(...) {}}
void Stream::push(Message m){std::lock_guard lk(mu_);queue_.push_back(std::move(m));cv_.notify_all();}
void Stream::write(std::span<const std::uint8_t>b){if(closed_)throw Error("stream is closed");Message m;m.type=MessageType::Data;m.stream_id=id_;m.payload.assign(b.begin(),b.end());owner_->send_message(m);}
std::vector<std::uint8_t> Stream::read(){std::unique_lock lk(mu_);cv_.wait(lk,[&]{return !queue_.empty()||closed_;});if(queue_.empty())return{};auto m=std::move(queue_.front());queue_.pop_front();if(m.type==MessageType::Error)throw Error(payload_string(m));if(m.type==MessageType::Close){closed_=true;return{};}return std::move(m.payload);}
void Stream::close(){if(closed_)return;closed_=true;if(owner_){Message m;m.type=MessageType::Close;m.stream_id=id_;owner_->send_message(m);}cv_.notify_all();}

ClientSession::ClientSession(const ConnInfo&i,KeyPair kp):info_(i),keypair_(kp){session_key_=derive_session_key(keypair_.private_key,info_.server_public,info_.preshared_key);}
ClientSession::~ClientSession(){close();}
DerpNode ClientSession::choose_node()const{if(!info_.nodes.empty())return info_.nodes.front();if(info_.region_id==0)throw Error("tailcat address contains no DERP relay");auto sel=fetch_derp_selection("https://tailcat.dev/derpmap.json","client",info_.region_id);return sel.nodes.front();}
void ClientSession::connect(){if(derp_)return;derp_=std::make_unique<DerpClient>(keypair_,choose_node());derp_->connect();receive_thread_=std::thread([this]{receive_loop();});}
std::shared_ptr<Stream> ClientSession::open(std::string target){if(!derp_)connect();auto id=next_stream_.fetch_add(1);auto s=std::shared_ptr<Stream>(new Stream(this,id));{std::lock_guard lk(streams_mu_);streams_[id]=s;}send_message(make_text_message(MessageType::Open,id,target));return s;}
void ClientSession::send_message(const Message&m){auto clear=encode_message(m);auto enc=encrypt_packet(clear,session_key_);derp_->send_to(info_.server_public,enc);}
void ClientSession::receive_loop(){try{while(!stopping_){auto p=derp_->receive();if(p.source!=info_.server_public)continue;auto clear=decrypt_packet(p.payload,session_key_);auto m=decode_message(clear);if(m.type==MessageType::Pong){std::uint64_t v=0;try{v=std::stoull(payload_string(m));}catch(...){continue;}{std::lock_guard lk(ping_mu_);last_pong_=v;}ping_cv_.notify_all();continue;}std::shared_ptr<Stream>s;{std::lock_guard lk(streams_mu_);auto it=streams_.find(m.stream_id);if(it!=streams_.end())s=it->second.lock();}if(s)s->push(std::move(m));}}catch(...){if(!stopping_){std::lock_guard lk(streams_mu_);for(auto&[_,w]:streams_)if(auto s=w.lock()){Message m=make_text_message(MessageType::Error,s->id(),"DERP session closed");s->push(std::move(m));}}}}
double ClientSession::ping(){if(!derp_)connect();auto n=now_nonce();{std::lock_guard lk(ping_mu_);last_pong_=0;}auto start=std::chrono::steady_clock::now();send_message(make_text_message(MessageType::Ping,0,u64_text(n)));std::unique_lock lk(ping_mu_);if(!ping_cv_.wait_for(lk,std::chrono::seconds(10),[&]{return last_pong_==n;}))throw Error("ping timed out");return std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();}
void ClientSession::close(){if(stopping_.exchange(true))return;if(derp_)derp_->close();if(receive_thread_.joinable()&&receive_thread_.get_id()!=std::this_thread::get_id())receive_thread_.join();derp_.reset();}

ServerSession::ServerSession(KeyPair kp,Key32 psk,DerpNode node,ServerOptions opt):keypair_(kp),preshared_key_(psk),node_(std::move(node)),options_(std::move(opt)){}
ServerSession::~ServerSession(){close();}
std::string ServerSession::stream_key(const Key32&p,std::uint32_t id)const{return hex(p)+":"+std::to_string(id);}
void ServerSession::send_message(const Key32&peer,const Key32&key,const Message&m){auto clear=encode_message(m);auto enc=encrypt_packet(clear,key);derp_->send_to(peer,enc);}
bool ServerSession::target_allowed(std::string_view host,std::uint16_t port)const{if(options_.exit_node)return true;bool local=host=="127.0.0.1"||host=="localhost"||host=="::1";if(!local)return false;return options_.allow_all_local_ports||options_.allowed_local_ports.contains(port);}
void ServerSession::start_socket_reader(std::shared_ptr<RemoteStream> rs,Key32 session_key){std::thread([this,rs,session_key]{try{std::array<std::uint8_t,32768>b{};for(;;){auto n=rs->socket->read_some(boost::asio::buffer(b));if(!n)break;Message m;m.type=MessageType::Data;m.stream_id=rs->id;m.payload.assign(b.begin(),b.begin()+n);send_message(rs->peer,session_key,m);}}catch(...){}try{Message c;c.type=MessageType::Close;c.stream_id=rs->id;send_message(rs->peer,session_key,c);}catch(...){}boost::system::error_code ec;rs->socket->close(ec);std::lock_guard lk(streams_mu_);streams_.erase(stream_key(rs->peer,rs->id));}).detach();}
void ServerSession::open_target(const Key32&peer,const Key32&session_key,const Message&m){
  auto target=payload_string(m);auto rs=std::make_shared<RemoteStream>();rs->peer=peer;rs->id=m.stream_id;
  if(target=="stdio"){
    if(!options_.stdio){send_message(peer,session_key,make_text_message(MessageType::Error,m.stream_id,"server is not in stdio mode"));return;}rs->stdio=true;{std::lock_guard lk(streams_mu_);streams_[stream_key(peer,m.stream_id)]=rs;}
    std::thread([this,rs,session_key]{try{std::array<std::uint8_t,32768>b{};while(std::cin){std::cin.read(reinterpret_cast<char*>(b.data()),b.size());auto n=std::cin.gcount();if(n<=0)break;Message d;d.type=MessageType::Data;d.stream_id=rs->id;d.payload.assign(b.begin(),b.begin()+n);send_message(rs->peer,session_key,d);}Message c;c.type=MessageType::Close;c.stream_id=rs->id;send_message(rs->peer,session_key,c);}catch(...) {}}).detach();return;
  }
  if(!target.starts_with("tcp:")){send_message(peer,session_key,make_text_message(MessageType::Error,m.stream_id,"unsupported target"));return;}
  try{auto[host,port]=parse_host_port(std::string_view(target).substr(4));if(!target_allowed(host,port))throw Error("target is not permitted by the server");auto sock=std::make_shared<boost::asio::ip::tcp::socket>(socket_io_);boost::asio::ip::tcp::resolver r(socket_io_);boost::asio::connect(*sock,r.resolve(host,std::to_string(port)));rs->socket=sock;{std::lock_guard lk(streams_mu_);streams_[stream_key(peer,m.stream_id)]=rs;}start_socket_reader(rs,session_key);}catch(const std::exception&e){send_message(peer,session_key,make_text_message(MessageType::Error,m.stream_id,e.what()));}
}
void ServerSession::handle_message(const Key32&peer,const Key32&session_key,const Message&m){
  if(m.type==MessageType::Ping){send_message(peer,session_key,make_text_message(MessageType::Pong,0,payload_string(m)));return;}if(m.type==MessageType::Open){open_target(peer,session_key,m);return;}std::shared_ptr<RemoteStream>rs;{std::lock_guard lk(streams_mu_);auto it=streams_.find(stream_key(peer,m.stream_id));if(it!=streams_.end())rs=it->second;}if(!rs)return;
  if(m.type==MessageType::Data){if(rs->stdio){std::lock_guard lk(stdio_mu_);std::cout.write(reinterpret_cast<const char*>(m.payload.data()),m.payload.size());std::cout.flush();}else if(rs->socket){std::lock_guard lk(rs->write_mu);boost::asio::write(*rs->socket,boost::asio::buffer(m.payload));}}
  else if(m.type==MessageType::Close){if(rs->socket){boost::system::error_code ec;rs->socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both,ec);rs->socket->close(ec);}std::lock_guard lk(streams_mu_);streams_.erase(stream_key(peer,m.stream_id));}
}
void ServerSession::run(){derp_=std::make_unique<DerpClient>(keypair_,node_);derp_->connect();while(!stopping_){auto p=derp_->receive();try{auto key=derive_session_key(keypair_.private_key,p.source,preshared_key_);auto clear=decrypt_packet(p.payload,key);auto m=decode_message(clear);handle_message(p.source,key,m);}catch(const std::exception&){/* unauthenticated/foreign traffic is ignored */}}}
void ServerSession::close(){if(stopping_.exchange(true))return;if(derp_)derp_->close();std::lock_guard lk(streams_mu_);for(auto&[_,s]:streams_)if(s->socket){boost::system::error_code ec;s->socket->close(ec);}streams_.clear();}

} // namespace tailcat
