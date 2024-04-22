#ifndef SIPDUMP_PCAP_NETWORK_H__
#define SIPDUMP_PCAP_NETWORK_H__

#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>

#include <pcap.h>
#include <apr.h>

APR_BEGIN_DECLS

/** 网络地址 */
struct network_addr {
    uint32_t ip; /** IP */
    uint16_t port; /** 端口 */
};

/** 网络socket对 */
struct network_socket_pair {
    uint8_t version;
    uint8_t protocol; /** 协议 */
    struct network_addr src; /** socket 源端信息 */
    struct network_addr dst; /** socket 目的端信息 */
};

struct network_pkt_t {
    /** PCAP原始数据 */
    struct pcap_pkthdr *pkt_header; /** 包头（从ethernet头开始） */
    const u_char *pkt_data; /** 包指针（从ethernet头开始） */
    apr_time_t timestamp; /** 时戳 */

    /** IP */
    uint8_t version;
    const struct iphdr *ipv4; /** IPV4头 */
    const struct ip6_hdr *ipv6; /** IPV6头 */
    struct { 
        uint8_t DF; /** Don't fragment */
        uint8_t MF; /** More fragments */
    } fragment; /** IPV4头中frag_off的解析 */
    u_int16_t offset; /** IPV4头中frag_off的解析 */

    /** TCP/UDP */
    const struct tcphdr *tcp; /** TCP头 */
    const struct udphdr *udp; /** UDP头 */
    struct network_socket_pair socket_pair;

    /** 应用数据 */
    const char *data; /** 指针 */
    apr_size_t size; /** 当前长度（有可能被分包） */
    apr_size_t total; /** 完整长度（被分包情况下的长度） */
};
/** 网络数据 */
typedef struct network_pkt_t network_pkt_t;

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
  #define CONST_BSWAP16(x)     ((uint16_t)(                        \
                             (((uint16_t)(x) >> 8) & 0x00FF)   | \
                             (((uint16_t)(x) << 8) & 0xFF00)))
  #define HTONS(x) CONST_BSWAP16(x)
#else
  #define HTONS(x) (x)
#endif

enum network_pkt_type_e {
    SIPDUMP_PKT_TYPE_UNKNOWN = -1,
    SIPDUMP_PKT_TYPE_SIP, /** SIP包 */
#ifdef SIPDUMP_MRCP
    SIPDUMP_PKT_TYPE_MRCP, /** MRCP包 */
#endif
    SIPDUMP_PKT_TYPE_RTP, /** RTP包 */
    SIPDUMP_PKT_TYPE_RTP_AUDIO, /** RTP AUDIO包 */
    SIPDUMP_PKT_TYPE_RTP_VIDEO, /** RTP VIDEO包 */
    SIPDUMP_PKT_TYPE_RTCP, /** RTCP包 */
    SIPDUMP_PKT_TYPE_RTCP_AUDIO, /** RTCP AUDIO包 */
    SIPDUMP_PKT_TYPE_RTCP_VIDEO, /** RTCP VIDEO包 */
    SIPDUMP_PKT_TYPE_MAX, /** 网络数据包类型最大值，用作数组下标 */
};
/** 网络数据包分类 */
typedef enum network_pkt_type_e network_pkt_type_e;

/*!
  \brief 获取网络IP包信息
  \param pkt_data 包数据
  \return 成功返回IP包信息（内存指向pkt_data），失败返回NULL
*/
const struct iphdr *sipdump_network_ip_get(const void *pkt_data);

/*!
  \brief 获取网络IP包信息
  \param ip_hdr IP头数据
  \return 成功返回IP包信息（内存指向ip_hdr），失败返回NULL
*/
const struct iphdr *sipdump_network_tunnel_ip_skip(const struct iphdr *ip_hdr);

/*!
  \brief 获取IP协议字符串
  \param protocol 协议
  \return 成功返回IP协议字符串，失败返回NULL
*/
const char *sipdump_network_protocol_str(uint8_t protocol);

/*!
  \brief 格式化socket对
  \param socket socket对信息
  \param buffer 字符串存储buffer
  \param size 字符串buffer最大长度
  \return buffer指针（链式表达）
*/
char *sipdump_network_socket_pair_str(const struct network_socket_pair *socket, char *buffer, apr_size_t size);

/*!
  \brief 格式化socket地址
  \param version 版本
  \param addr 地址信息
  \param buffer 字符串存储buffer
  \param size 字符串buffer最大长度
  \return buffer指针（链式表达）
*/
char* sipdump_network_socket_str(uint8_t version, const struct network_addr *addr, char *buffer, apr_size_t size);

APR_END_DECLS

#endif