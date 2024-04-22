#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <apr_strings.h>

#include "sipdump_log.h"
#include "sipdump_util.h"
#include "sipdump_network.h"

const struct iphdr *sipdump_network_ip_get(const void *pkt_data) {
    assert(pkt_data);
    // skip source & destination MACs (12 bytes = 6 uint16s)
    const uint16_t *pkt_ethertype = ((uint16_t *)pkt_data) + 6;
    // possible 802.1Q, 802.1ad, and Q-in-Q formats:
    // as indexed from pkt_ethertype[]:
    //   [0]    [1]   [2]  [3]   [4]  [5]
    // 0x0800  IP                         <- untagged
    // 0x86dd  IP6                        <- untagged IPv6
    // 0x8100  tag   0x0800 IP            <- 802.1Q
    // 0x8100  tag   0x88dd IP6           <- 802.1Q, then IPv6
    // 0x8100  tag   0x8864 ..  ..     .. <- 802.1Q, then PPPoE
    // 0x8100  tag   0x8100 tag 0x0800 IP <- non-standard Q-in-Q
    // 0x9100  tag   0x8100 tag 0x0800 IP <- old standard Q-in-Q
    // 0x88a8  tag   0x8100 tag 0x0800 IP <- 802.1ad Q-in-Q
    // 0x8864 0x1100 sessid len 0x0021 IP <- RFC2516 PPPoE Session Stage IPv4
    // 0x8864 0x1100 sessid len 0x0057 IP <- RFC2516 PPPoE Session Stage IPv6
    switch(pkt_ethertype[0]){
        case HTONS(ETH_P_IP):
            return (struct iphdr*)(pkt_ethertype + 1);
        case HTONS(ETH_P_IPV6):
            return (struct iphdr*)(pkt_ethertype + 1);
        case HTONS(ETH_P_8021Q):
            if (pkt_ethertype[2] == htons(ETH_P_IP) ||
                pkt_ethertype[2] == htons(ETH_P_IPV6)){
                return (struct iphdr*)(pkt_ethertype + 3);
            } else if (pkt_ethertype[2] == htons(ETH_P_PPP_SES)){
                // recurse
                return sipdump_network_ip_get((uint16_t *)pkt_data+2);
            }
            // fallthrough
        case HTONS(ETH_P_QINQ1):
        case HTONS(ETH_P_8021AD):
            if (pkt_ethertype[2] == htons(ETH_P_8021Q) &&
                pkt_ethertype[4] == htons(ETH_P_IP)){
                return (struct iphdr*)(pkt_ethertype + 5);
            }
            goto fail;
        case HTONS(ETH_P_PPP_SES):
            if (pkt_ethertype[1] == htons(0x1100) &&
                (pkt_ethertype[4] == htons(0x0021) ||
                 pkt_ethertype[4] == htons(0x0057))){
                return (struct iphdr*)(pkt_ethertype + 5);
            }
            if (pkt_ethertype[4] == htons(0xc021)){ // LCP
                goto fail;
            }
    }
fail:
    // bail on unfamiliar ethertype
    // printf("Can't parse Ethernet tags: %04x %04x %04x %04x %04x %04x\n",
    //     htons(pkt_ethertype[0]),
    //     htons(pkt_ethertype[1]),
    //     htons(pkt_ethertype[2]),
    //     htons(pkt_ethertype[3]),
    //     htons(pkt_ethertype[4]),
    //     htons(pkt_ethertype[5]));
    return NULL;
}

const struct iphdr *sipdump_network_tunnel_ip_skip(const struct iphdr *ip_hdr) {
    assert(ip_hdr);
    const struct ip6_hdr *ipv6 = (const struct ip6_hdr*)ip_hdr;
    if (ipv6->ip6_vfc == 6 && ipv6->ip6_nxt == 4) {
        return (const struct iphdr*)(((char*)ip_hdr) + sizeof(*ipv6));
    }
    return ip_hdr;
}

const char *sipdump_network_protocol_str(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP: return "TCP";
        default: break;
    }
    return "UNKNOWN";
}

char *sipdump_network_socket_str(uint8_t version, const struct network_addr *addr, char *buffer, apr_size_t size) {
    assert(addr);
    assert(buffer);
    char socket[32] = {'\0'};
    snprintf(buffer, size, "%s:%u",  
        sipdump_network_ntop(version, addr->ip, socket, sizeof(socket)),
        addr->port
    );
    return buffer;
}

char *sipdump_network_socket_pair_str(const struct network_socket_pair *socket, char *buffer, apr_size_t size) {
    assert(socket);
    assert(buffer);
    char src[32] = {'\0'};
    char dst[32] = {'\0'};
    snprintf(buffer, size, "%s %s:%u <-> %s:%u",  
        sipdump_network_protocol_str(socket->protocol),
        sipdump_network_ntop(socket->version, socket->src.ip, src, sizeof(src)),
        socket->src.port,
        sipdump_network_ntop(socket->version, socket->dst.ip, dst, sizeof(dst)),
        socket->dst.port
    );
    return buffer;
}

