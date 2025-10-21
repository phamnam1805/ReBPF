#include <net/if.h>
#include <stdio.h>

int main() {
    unsigned int ifindex = if_nametoindex("lo");
    printf("ifindex of lo = %u\n", ifindex);
    return 0;
}