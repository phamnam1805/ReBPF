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

    struct packet_t pkt = { 0 };

    pkt.src_ip = saddr;
    pkt.src_port = __bpf_htons(sport);

    pkt.dst_ip = daddr;
    pkt.dst_port = dport;

    
    pkt.seq = __bpf_htonl(seq);
    pkt.ack_seq = __bpf_htonl(ack_seq);
    pkt.tcp_flags = tcp_flags;
    pkt.ts = bpf_ktime_get_ns();
    
    // __be32 d_addr = 0;
    // __be16 d_port = 0;
    // bpf_probe_read_kernel(&d_addr, sizeof(d_addr), &sk->__sk_common.skc_daddr);
    // bpf_probe_read_kernel(&d_port, sizeof(d_port), &sk->__sk_common.skc_dport);
    __be32 s_addr = 0;
    __be16 s_port = 0;
    bpf_probe_read_kernel(&s_addr, sizeof(s_addr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&s_port, sizeof(s_port), &sk->__sk_common.skc_num);
    // bpf_printk("I got u, seq=%u, ack_seq=%u, flags=0x%x, daddr=0x%x, dport=%u\n",
    //         seq, ack_seq, tcp_flags, d_addr, d_port);
    bpf_printk("Fentry, seq=%u, ack_seq=%u, flags=0x%x, saddr=0x%x, sport=%u\n",
            seq, ack_seq, tcp_flags, s_addr, s_port);
    if (bpf_ringbuf_output(&retransmit_pipe, &pkt, sizeof(pkt), 0) < 0) {
        bpf_printk("Failed to send to ringbuf\n");
        return 0;
    }
    return 0;
}

SEC("fentry/__tcp_transmit_skb")
int BPF_PROG(fentry__tcp_transmit_skb, struct sock *sk, struct sk_buff *skb) {
    
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

    struct packet_t pkt = { 0 };

    pkt.src_ip = saddr;
    pkt.src_port = __bpf_htons(sport);

    pkt.dst_ip = daddr;
    pkt.dst_port = dport;

    pkt.seq = __bpf_htonl(seq);
    pkt.ack_seq = __bpf_htonl(ack_seq);
    pkt.tcp_flags = tcp_flags;
    pkt.ts = bpf_ktime_get_ns();

    // __be32 s_addr = 0;
    // __be16 s_port = 0;
    // bpf_probe_read_kernel(&s_addr, sizeof(s_addr), &sk->__sk_common.skc_rcv_saddr);
    // bpf_probe_read_kernel(&s_port, sizeof(s_port), &sk->__sk_common.skc_num);
    // bpf_printk("I got u, seq=%u, ack_seq=%u, flags=0x%x, daddr=0x%x, dport=%u\n",
    //         seq, ack_seq, tcp_flags, d_addr, d_port);
    // bpf_printk("Kprobe, seq=%u, ack_seq=%u, flags=0x%x, saddr=0x%x, sport=%u\n",
    //         seq, ack_seq, tcp_flags, s_addr, s_port);
    if (bpf_ringbuf_output(&transmit_pipe, &pkt, sizeof(pkt), 0) < 0) {
        bpf_printk("Failed to send to ringbuf\n");
        return 0;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";