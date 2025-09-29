#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/types.h>

struct retr_packet_t {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __be32 seq; 
    __be32 ack_seq;
    __s32 ret;
};

int main() {
    printf("src_ip: size = %lu, offset = %lu\n", sizeof(((struct retr_packet_t *)0)->src_ip), offsetof(struct retr_packet_t, src_ip));
    printf("dst_ip: size = %lu, offset = %lu\n", sizeof(((struct retr_packet_t *)0)->dst_ip), offsetof(struct retr_packet_t, dst_ip));
    printf("src_port: size = %lu, offset = %lu\n", sizeof(((struct retr_packet_t *)0)->src_port), offsetof(struct retr_packet_t, src_port));
    printf("dst_port: size = %lu, offset = %lu\n", sizeof(((struct retr_packet_t *)0)->dst_port), offsetof(struct retr_packet_t, dst_port));
    printf("seq: size = %lu, offset = %lu\n", sizeof(((struct retr_packet_t *)0)->seq), offsetof(struct retr_packet_t, seq));
    printf("ack_seq: size = %lu, offset = %lu\n", sizeof(((struct retr_packet_t *)0)->ack_seq), offsetof(struct retr_packet_t, ack_seq));
    printf("ret: size = %lu, offset = %lu\n", sizeof(((struct retr_packet_t *)0)->ret), offsetof(struct retr_packet_t, ret));
    return 0;
}