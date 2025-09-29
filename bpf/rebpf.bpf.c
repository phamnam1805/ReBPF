#include "common.h"

volatile __be16 match_port = __bpf_htons(5201);
volatile __be32 match_ip = 0x32a280a;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  /* 512 KB */
} retransmit_pipe SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  /* 512 KB */
} transmit_pipe SEC(".maps");

SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(fentry_tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb, int segs){
    __u16 skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (skc_family != AF_INET) {
        return 0;
    }

    struct in_addr daddr;
    daddr.s_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    if(daddr.s_addr != __bpf_ntohl(match_ip) || dport != match_port){
        return 0;
    }

    struct tcp_skb_cb *tcp = (struct tcp_skb_cb*)BPF_CORE_READ(skb, cb);
    __u32 seq = BPF_CORE_READ(tcp, seq);
    __u32 ack_seq = BPF_CORE_READ(tcp, ack_seq);
    __u8 tcp_flags = BPF_CORE_READ(tcp, tcp_flags);

    struct in_addr saddr;
    saddr.s_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    struct retr_packet_t pkt = { 0 };
    pkt.src_ip = saddr;
    pkt.src_port = __bpf_htons(sport);
    pkt.dst_ip = daddr;
    pkt.dst_port = dport;
    pkt.seq = __bpf_htonl(seq);
    pkt.ack_seq = __bpf_htonl(ack_seq);
    
    struct packet_key_t pkt_key = { 0 };
    pkt_key.src_ip = saddr;
    pkt_key.src_port = __bpf_htons(sport);
    pkt_key.dst_ip = daddr;
    pkt_key.dst_port = dport;
    pkt_key.seq = __bpf_htonl(seq);

    // __be32 d_addr = 0;
    // __be16 d_port = 0;
    // bpf_probe_read_kernel(&d_addr, sizeof(d_addr), &sk->__sk_common.skc_daddr);
    // bpf_probe_read_kernel(&d_port, sizeof(d_port), &sk->__sk_common.skc_dport);
    // __be32 s_addr = 0;
    // __be16 s_port = 0;
    // bpf_probe_read_kernel(&s_addr, sizeof(s_addr), &sk->__sk_common.skc_rcv_saddr);
    // bpf_probe_read_kernel(&s_port, sizeof(s_port), &sk->__sk_common.skc_num);

    // bpf_printk("I got u at fentry, seq=%u, ack_seq=%u, daddr=0x%x, dport=%u\n",
    //         seq, ack_seq, d_addr, d_port);

    __u8 val = 1;
    bpf_map_update_elem(&retr_packet_map, &pkt_key, &val, BPF_ANY);
    // if (bpf_ringbuf_output(&retransmit_pipe, &pkt, sizeof(pkt), 0) < 0) {
    //     bpf_printk("Failed to send to ringbuf\n");
    //     return 0;
    // }
    return 0;
}


SEC("fexit/tcp_retransmit_skb")
int BPF_PROG(fexit_tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb, int segs, int ret){
    __u16 skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (skc_family != AF_INET) {
        return 0;
    }

    struct in_addr daddr;
    daddr.s_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    if(daddr.s_addr != __bpf_ntohl(match_ip) || dport != match_port){
        return 0;
    }

    struct tcp_skb_cb *tcp = (struct tcp_skb_cb*)BPF_CORE_READ(skb, cb);
    __u32 seq = BPF_CORE_READ(tcp, seq);
    __u32 ack_seq = BPF_CORE_READ(tcp, ack_seq);
    __u8 tcp_flags = BPF_CORE_READ(tcp, tcp_flags);

    struct in_addr saddr;
    saddr.s_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    struct retr_packet_t pkt = { 0 };
    pkt.src_ip = saddr;
    pkt.src_port = __bpf_htons(sport);
    pkt.dst_ip = daddr;
    pkt.dst_port = dport;

    pkt.seq = __bpf_htonl(seq);
    pkt.ack_seq = __bpf_htonl(ack_seq);
    pkt.ret = ret;
    
    struct packet_key_t pkt_key = { 0 };
    pkt_key.src_ip = saddr;
    pkt_key.src_port = __bpf_htons(sport);
    pkt_key.dst_ip = daddr;
    pkt_key.dst_port = dport;
    pkt_key.seq = __bpf_htonl(seq);

    // __be32 d_addr = 0;
    // __be16 d_port = 0;
    // bpf_probe_read_kernel(&d_addr, sizeof(d_addr), &sk->__sk_common.skc_daddr);
    // bpf_probe_read_kernel(&d_port, sizeof(d_port), &sk->__sk_common.skc_dport);
    // __be32 s_addr = 0;
    // __be16 s_port = 0;
    // bpf_probe_read_kernel(&s_addr, sizeof(s_addr), &sk->__sk_common.skc_rcv_saddr);
    // bpf_probe_read_kernel(&s_port, sizeof(s_port), &sk->__sk_common.skc_num);

    // bpf_printk("I got u at fexit, seq=%u, ack_seq=%u, daddr=0x%x, dport=%u\n",
    //         seq, ack_seq, d_addr, d_port);
    __u8 *found = bpf_map_lookup_elem(&retr_packet_map, &pkt_key);
    if (found) {
        bpf_map_delete_elem(&retr_packet_map, &pkt_key);
        if (bpf_ringbuf_output(&retransmit_pipe, &pkt, sizeof(pkt), 0) < 0) {
            bpf_printk("Failed to send to ringbuf\n");
            return 0;
        }
    }
    return 0;
}

static inline int handle_ip_packet(void* head, void* tail, uint32_t* offset, struct tc_packet_t* pkt) {
    struct ethhdr* eth = head;
    struct iphdr* ip;

    switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
        *offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

        if (head + (*offset) > tail) { // If the next layer is not IP, let the packet pass
            return TC_ACT_OK;
        }

        ip = head + sizeof(struct ethhdr);

        if (ip->protocol != IPPROTO_TCP) {
            return TC_ACT_OK;
        }
        
        pkt->src_ip.s_addr = ip->saddr;
        pkt->dst_ip.s_addr = ip->daddr;

        pkt->protocol = ip->protocol;
        pkt->ttl = ip->ttl;

        return 1; 

    case ETH_P_IPV6:
        return TC_ACT_OK;
    default:
        return TC_ACT_OK;
    }
}

static inline int handle_ip_segment(void* head, void* tail, uint32_t* offset, struct tc_packet_t* pkt) {
    struct tcphdr* tcp;
    struct udphdr* udp;

    switch (pkt->protocol) {
    case IPPROTO_TCP:
        tcp = head + *offset;
        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        pkt->seq = tcp->seq;
        pkt->ack_seq = tcp->ack_seq;
        // pkt->syn = tcp->syn;
        // pkt->ack = tcp->ack;
        // pkt->ts = bpf_ktime_get_ns();
        return 1;
    case IPPROTO_UDP:
        return TC_ACT_OK;
    default:
        return TC_ACT_OK;
    }
}

SEC("tc")
int drop_retransmit(struct __sk_buff *skb) {

    if (bpf_skb_pull_data(skb, 0) < 0) {
        return TC_ACT_OK;
    }

    if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
        return TC_ACT_OK;
    }

    void* head = (void*)(long)skb->data;     // Start of the packet data
    void* tail = (void*)(long)skb->data_end; // End of the packet data

    if (head + sizeof(struct ethhdr) > tail) { // Not an Ethernet frame
        return TC_ACT_OK;
    }

    struct tc_packet_t pkt = { 0 };

    uint32_t offset = 0;

    if (handle_ip_packet(head, tail, &offset, &pkt) == TC_ACT_OK) {
        return TC_ACT_OK;
    }

    if (head + offset + sizeof(struct tcphdr) > tail || head + offset + sizeof(struct udphdr) > tail) {
        return TC_ACT_OK;
    }

    if (handle_ip_segment(head, tail, &offset, &pkt) == TC_ACT_OK) {
        return TC_ACT_OK;
    }

    if (pkt.dst_port != match_port || pkt.dst_ip.s_addr != bpf_ntohl(match_ip)){
        return TC_ACT_OK; 
    }

    struct packet_key_t pkt_key = { 0 };
    pkt_key.src_ip = pkt.src_ip;
    pkt_key.src_port = pkt.src_port;
    pkt_key.dst_ip = pkt.dst_ip;
    pkt_key.dst_port = pkt.dst_port;
    pkt_key.seq = pkt.seq;
    // bpf_printk("at tc, seq=%u, ack_seq=%u", pkt_key.seq);
    __u8 *found = bpf_map_lookup_elem(&retr_packet_map, &pkt_key);
    if (found) {
        bpf_printk("Found retr packet at tc, this packet will be dropped");
        return TC_ACT_SHOT;
        // return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";