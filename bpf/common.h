#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>


#define ETH_P_IP	        0x0800
#define ETH_P_IPV6	        0x86DD

#define AF_INET 2
#define AF_INET6 10

#define PACKET_BROADCAST	1
#define PACKET_MULTICAST	2

#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN   4

#define TH_FIN  0x01    // 0000 0001
#define TH_SYN  0x02    // 0000 0010  
#define TH_RST  0x04    // 0000 0100

#define TCP_ESTABLISHED  1
#define TCP_CLOSE_WAIT   8

struct retr_packet_t {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __be32 seq; 
    __be32 ack_seq;
    __s32 ret;
};

struct tc_packet_t {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 ttl;
    __be32 seq; 
    __be32 ack_seq;
};

struct packet_key_t {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __be32 seq; 
    __be32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct packet_key_t);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} retr_packet_map SEC(".maps");