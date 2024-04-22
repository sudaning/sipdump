#include <stdio.h>
#include "sipdump_util.h"


int test_sipdump_network_pton() {
    uint32_t ip = sipdump_network_pton("192.168.1.1");
    printf("ip: 0x%08X\n", ip);
    return 0;
}