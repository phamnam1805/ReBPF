#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/types.h>

struct packet_t {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __be32 seq; 
    __be32 ack_seq;
    __u8 tcp_flags;
    uint64_t ts;
};

int main() {
    printf("src_ip: size = %lu, offset = %lu\n", sizeof(((struct packet_t *)0)->src_ip), offsetof(struct packet_t, src_ip));
    printf("dst_ip: size = %lu, offset = %lu\n", sizeof(((struct packet_t *)0)->dst_ip), offsetof(struct packet_t, dst_ip));
    printf("src_port: size = %lu, offset = %lu\n", sizeof(((struct packet_t *)0)->src_port), offsetof(struct packet_t, src_port));
    printf("dst_port: size = %lu, offset = %lu\n", sizeof(((struct packet_t *)0)->dst_port), offsetof(struct packet_t, dst_port));
    printf("seq: size = %lu, offset = %lu\n", sizeof(((struct packet_t *)0)->seq), offsetof(struct packet_t, seq));
    printf("ack_seq: size = %lu, offset = %lu\n", sizeof(((struct packet_t *)0)->ack_seq), offsetof(struct packet_t, ack_seq));
    printf("tcp_flags: size = %lu, offset = %lu\n", sizeof(((struct packet_t *)0)->tcp_flags), offsetof(struct packet_t, tcp_flags));
    printf("ts: size = %lu, offset = %lu\n", sizeof(((struct packet_t *)0)->ts), offsetof(struct packet_t, ts));
    return 0;
}