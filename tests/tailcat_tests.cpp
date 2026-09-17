#include "tailcat/address.hpp"
#include "tailcat/crypto.hpp"
#include "tailcat/protocol.hpp"
#include <cassert>
#include <iostream>

using namespace tailcat;
int main(){
  crypto_init();
  ConnInfo a;auto kp=make_keypair();a.server_public=kp.public_key;a.preshared_key=random_key32();a.region_id=302;a.nodes.push_back(DerpNode{.host_name="derp.example.test",.derp_port=443});auto s=encode_address(a);auto b=parse_address(s);assert(b.server_public==a.server_public);assert(b.preshared_key==a.preshared_key);assert(b.region_id==302);assert(b.nodes.size()==1);assert(b.nodes[0].host_name=="derp.example.test");
  auto client=make_keypair(),server=make_keypair();auto psk=random_key32();auto ck=derive_session_key(client.private_key,server.public_key,psk);auto sk=derive_session_key(server.private_key,client.public_key,psk);assert(ck==sk);Message m=make_text_message(MessageType::Data,7,"hello");auto clear=encode_message(m);auto enc=encrypt_packet(clear,ck);auto dec=decrypt_packet(enc,sk);auto out=decode_message(dec);assert(out.stream_id==7);assert(payload_string(out)=="hello");
  std::cout<<"ok\n";
}
