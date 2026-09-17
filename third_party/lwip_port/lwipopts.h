#pragma once

/* Tailcat runs one lwIP instance entirely in-process without an OS networking
 * thread. Tailcat's peer network is IPv6-only; host-side forwarding can still
 * target IPv4 using normal host sockets outside this userspace stack.
 */
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0

#define LWIP_IPV4 0
#define LWIP_IPV6 1
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_RAW 1
#define LWIP_ICMP 0
#define LWIP_ICMP6 1

/* Tailcat's virtual interface carries raw IP packets, never Ethernet frames.
 * Disable every Ethernet/ARP-dependent feature so the raw-IP netif does not
 * pull in an unused L2 implementation.
 */
#define LWIP_ETHERNET 0
#define LWIP_ARP 0
#define PPPOE_SUPPORT 0
#define LWIP_IGMP 0
#define LWIP_SINGLE_NETIF 1
#define LWIP_IPV6_SCOPES 0

#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_DNS 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_IPV6_DHCP6 0
#define LWIP_IPV6_MLD 0

#define MEM_ALIGNMENT 8
#define MEM_SIZE (256 * 1024)
#define MEMP_NUM_TCP_PCB 32
#define MEMP_NUM_TCP_PCB_LISTEN 16
#define MEMP_NUM_TCP_SEG 128
#define MEMP_NUM_UDP_PCB 32
#define TCP_MSS 1280
#define TCP_WND (16 * TCP_MSS)
#define TCP_SND_BUF (16 * TCP_MSS)
#define TCP_SND_QUEUELEN 64

#define LWIP_CHECKSUM_CTRL_PER_NETIF 0
#define CHECKSUM_GEN_UDP 1
#define CHECKSUM_GEN_TCP 1
#define CHECKSUM_CHECK_UDP 1
#define CHECKSUM_CHECK_TCP 1

#define LWIP_STATS 0
#define LWIP_DEBUG 0
