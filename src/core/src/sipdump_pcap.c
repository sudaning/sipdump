#include <assert.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include "sipdump_config.h"
#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_opt.h"
#include "sipdump_network.h"
#include "sipdump_fragment.h"
#include "sipdump_session.h"
#include "sipdump_sip.h"
#include "sipdump_plugins.h"
#ifdef SIPDUMP_MRCP
#include "sipdump_mrcp.h"
#endif
#include "sipdump_pcap.h"

struct sipdump_pcap_t {
    apr_pool_t *pool; /** 内存池 */
    sipdump_opt_t *opt; /** 配置器 */

    int running;
    apr_thread_mutex_t *mutex;
    apr_thread_cond_t *cond;
    apr_thread_t *thread;
    apr_thread_start_t thread_fun;

    pcap_t *handle; /** pcap句柄 */
    int offline; /** 文件读包模式 */
    int dlt;
    int offset_to_ip;
};
typedef struct sipdump_pcap_t sipdump_pcap_t;

static void *APR_THREAD_FUNC _pcap_run(apr_thread_t *thread, void *arg);

apr_status_t sipdump_pcap_create(sipdump_pcap_t **pcap) {

    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, NULL);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP create pool error: %d", status);
        return status;
    }

    sipdump_pcap_t *p = apr_pcalloc(pool, sizeof(sipdump_pcap_t));
    if (!p) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP pcalloc from pool error");
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }

    apr_thread_mutex_t *mutex = NULL;
    status = apr_thread_mutex_create(&mutex, APR_THREAD_MUTEX_DEFAULT, pool);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP create mutex error: %d", status);
        apr_pool_destroy(pool);
        return status;
    }

    apr_thread_cond_t *cond = NULL;
    status = apr_thread_cond_create(&cond, pool);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP create cond error: %d", status);
        apr_thread_mutex_destroy(mutex);
        apr_pool_destroy(pool);
        return status;
    }

    p->pool = pool;
    p->mutex = mutex;
    p->cond = cond;
    p->running = FALSE;
    p->thread = NULL;
    p->thread_fun = _pcap_run;

    *pcap = p;
    return APR_SUCCESS;
}

apr_status_t sipdump_pcap_destroy(sipdump_pcap_t *pcap) {
    assert(pcap);
    if (pcap->pool) {
        apr_pool_destroy(pcap->pool);
    }
    return APR_SUCCESS;
}

apr_status_t sipdump_pcap_init_opt(sipdump_pcap_t *pcap, sipdump_opt_t *opt) {
    assert(pcap);
    assert(opt);
    
    /** 打开网络或pcap文件 */
    const char *eth_name = sipdump_opt_eth_name_get(opt);
    pcap_t *handle = NULL;
    if (eth_name) {
        char err[PCAP_ERRBUF_SIZE] = {'\0'};
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP capture on interface: %s", eth_name);
        handle = pcap_create(eth_name, err);
        if (!handle){
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't open interface '%s': pcap_create(): %s", eth_name, err);
            goto error;
        }
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP version: %s", pcap_lib_version());
        if (pcap_set_snaplen(handle, 9000)){
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't open interface '%s': pcap_set_snaplen(9000): %s", eth_name, pcap_geterr(handle));
            goto error;
        }

        int promisc = sipdump_opt_promisc_get(opt);
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP promisc: %d", promisc);
        if (pcap_set_promisc(handle, promisc)){
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't open interface '%s': pcap_set_promisc(opt_promisc): %s", eth_name, pcap_geterr(handle));
            goto error;
        }

        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP capture timeout: %d", 1000);
        if (pcap_set_timeout(handle, 1000)){
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't open interface '%s': pcap_set_timeout(1000): %s", eth_name, pcap_geterr(handle));
            goto error;
        }
        int pcap_buffer_size = sipdump_opt_pcap_buffer_size_get(opt);
        if (pcap_buffer_size > 0) {
            /** setting pcap_set_buffer_size to bigger values helps to deal with packet drops under high load
               libpcap > 1.0.0 if required for pcap_set_buffer_size
               for libpcap < 1.0.0 instead, this should be controled by /proc/sys/net/core/rmem_default
            */
            SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP buffer size: %d", pcap_buffer_size);
            if (pcap_set_buffer_size(handle, pcap_buffer_size)) {
                SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't open interface '%s': pcap_set_buffer_size(): %s", eth_name, pcap_geterr(handle));
                goto error;
            }
        }
        if (pcap_activate(handle)) {
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't open interface '%s': pcap_activate(): %s", eth_name, pcap_geterr(handle));
            goto error;
        }
        pcap->offline = FALSE;
    } else {
        const char *pcap_name = sipdump_opt_pcap_name_get(opt);
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP Reading file: %s", pcap_name);
        if (!pcap_name) {
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't open pcap file '%s'", pcap_name);
            goto error;
        }
        char err[PCAP_ERRBUF_SIZE] = {'\0'};
        handle = pcap_open_offline(pcap_name, err);
        if (!handle) {
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't open pcap file '%s': %s", pcap_name, err);
            goto error;
        }
        pcap->offline = TRUE;
    }

    /** 编译并应用网卡过滤器 */
    struct bpf_program fp;
    const char *pcap_filter = sipdump_opt_pcap_filter_get(opt);
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP filter: %s", pcap_filter);
    if (!SIPDUMP_ZSTR(pcap_filter)) {
        if (pcap_compile(handle, &fp, pcap_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't compile filter '%s': %s", pcap_filter, pcap_geterr(handle));
            goto error;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP Couldn't set filter '%s': %s", pcap_filter, pcap_geterr(handle));
            goto error;
        }
    }

    pcap->dlt = pcap_datalink(handle);
	switch (pcap->dlt) {
	    case DLT_EN10MB:
            pcap->offset_to_ip = sizeof(struct ethhdr);
            break;
	    case DLT_LINUX_SLL:
            pcap->offset_to_ip = 16;
            break;
	    case DLT_RAW:
            pcap->offset_to_ip = 0;
            break;
	    default: 
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP unknown interface type (%d).", pcap->dlt);
            goto error;
	}
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP datalink: %d", pcap->dlt);
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP offset to ip: %d", pcap->offset_to_ip);

    pcap->handle = handle;
    pcap->opt = opt;
    return APR_SUCCESS;

error:
    if (handle) {
        pcap_close(handle);
    }
    return APR_EINIT;
}

apr_status_t sipdump_pcap_run(sipdump_pcap_t *pcap) {
    assert(pcap);

    apr_thread_t *thread = NULL;
    apr_status_t status = apr_thread_create(&thread, NULL, pcap->thread_fun, pcap, pcap->pool);
    if (status != APR_SUCCESS) {
        return status;
    }
    pcap->thread = thread;

    /** 等待线程启动 */
    apr_thread_mutex_lock(pcap->mutex);
    apr_thread_cond_wait(pcap->cond, pcap->mutex);
    apr_thread_mutex_unlock(pcap->mutex);
    return APR_SUCCESS;
}

apr_status_t sipdump_pcap_stop(sipdump_pcap_t *pcap) {
    assert(pcap);
    SIPDUMP_LOG(SIPDUMP_PRIO_NOTICE, "PCAP thread is stopping");
    apr_thread_mutex_lock(pcap->mutex);
    pcap->running = FALSE;
    apr_thread_mutex_unlock(pcap->mutex);
    return APR_SUCCESS;
}

apr_status_t sipdump_pcap_wait_exit(sipdump_pcap_t *pcap) {
    assert(pcap);
    apr_status_t ret = APR_EBUSY;
    apr_thread_join(&ret, pcap->thread);
    SIPDUMP_LOG(SIPDUMP_PRIO_NOTICE, "PCAP thread is exited. status: %d", ret);
    return ret;
}

struct pkt_format_line {
    const char *name;
    u_int8_t protocol;
    apr_size_t len;
};

#define BUFFER_FIL_CHAR(buffer, buffer_max, offset, chr) if (offset + 1 < buffer_max) { buffer[offset++] = chr; }

static int network_pkt_show_head(char *buffer, int buffer_max, int offset, apr_size_t byte_max, int *split_line_len) {

    int before_offset = offset;
    offset += snprintf(buffer + offset, buffer_max - offset, "           bytes | ");
    unsigned int i = 0;
    for (i = 0; i < byte_max; i++) {
        offset += snprintf(buffer + offset, buffer_max - offset, "%02u ", i + 1);
        if ((i + 1) % 8 == 0) {
            BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
        }
    }
    BUFFER_FIL_CHAR(buffer, buffer_max, offset, '|');
    BUFFER_FIL_CHAR(buffer, buffer_max, offset, '\n');
    
    *split_line_len = offset - before_offset - 1;
    for (i = 0; i < *split_line_len; i++) {
        BUFFER_FIL_CHAR(buffer, buffer_max, offset, '-');
    }
    BUFFER_FIL_CHAR(buffer, buffer_max, offset, '\n');

    return offset;
}

static int network_pkt_show_body(char *buffer, int buffer_max, int offset, apr_size_t byte_max, const struct iphdr *ipv4_hdr, const u_char *pkt_data, apr_size_t pkt_size) {

    /** 协议层 */
    struct pkt_format_line prot[5] = {
        {"ETH", 254, sizeof(struct ethhdr)}, 
        {"IP ", IPPROTO_IP, sizeof(struct iphdr)}, 
        {"APP", IPPROTO_RAW, 16},
        {"APP", IPPROTO_RAW, 16},
        {"APP", IPPROTO_RAW, 16},
    };

    if (ipv4_hdr) {
        if (IPPROTO_UDP == ipv4_hdr->protocol) {
            prot[2].protocol = IPPROTO_UDP;
            prot[2].name = "UDP";
            prot[2].len = sizeof(struct udphdr);
        } else if (IPPROTO_TCP == ipv4_hdr->protocol) {
            prot[2].protocol = IPPROTO_TCP;
            prot[2].name = "TCP";
            prot[2].len = sizeof(struct tcphdr);
        }
    }
    int prot_index = 0;
    int byte_limit = 0;
    int byte_offset = 0;

    int i = 0;
    for (i = 0; i < pkt_size; i++) {
        if (prot_index >= sipdump_arraylen(prot)) {
            break;
        }
        
        /** 每行起始 */
        if (!byte_offset) {
            byte_limit += prot[prot_index].len;
            offset += snprintf(buffer + offset, buffer_max - offset,  
                " *%-3s 0x%08X |", prot[prot_index].name, &pkt_data[i]);
        }
        
        /** 每8个字符输出一个空格 */
        if (byte_offset % 8 == 0) {
            BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
        }
        
        /** 输出内容 */
        offset += snprintf(buffer + offset, buffer_max - offset,  
            "%02x ", 0xFF & pkt_data[i]);
        
        if (i + 1 == byte_limit) {

#if 0
            /** 在末尾添加ascii字符 */
            int j = 0;
            if (prot[prot_index].protocol == IPPROTO_RAW) {
                offset += snprintf(buffer + offset, buffer_max - offset,  
                    "             | ");
                for (j = byte_limit - prot[prot_index].len; j < byte_limit; j++) {
                    if (32 <= pkt_data[j] && pkt_data[j] <= 126) {
                        if (offset + 1 < buffer_max) {
                            buffer[offset++] = pkt_data[j];
                        }
                    } else if (pkt_data[j] == '\r') {
                        if (offset + 2 < buffer_max) {
                            buffer[offset++] = '\\';
                            buffer[offset++] = 'r';
                        }
                    } else if (pkt_data[j] == '\n') {
                        if (offset + 2 < buffer_max) {
                            buffer[offset++] = '\\';
                            buffer[offset++] = 'n';
                        }
                    } else {
                        if (offset + 1 < buffer_max) {
                            buffer[offset++] = '*';
                        }
                    }
                }
            }
#endif
            prot_index++;
            int m = 0;
            for (m = byte_offset; m < byte_max - 1; m++) {
                BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
                BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
                BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
                if (m % 8 == 0) {
                    BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
                }
            }
            BUFFER_FIL_CHAR(buffer, buffer_max, offset, '|');
            BUFFER_FIL_CHAR(buffer, buffer_max, offset, '\n');
            byte_offset = 0;
        } else {
            byte_offset++;
        }
    }

    if (i == pkt_size && byte_offset != 0) {
        int m = 0;
        for (m = byte_offset; m < byte_max; m++) {
            BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
            BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
            BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
            if (m % 8 == 0) {
                BUFFER_FIL_CHAR(buffer, buffer_max, offset, ' ');
            }
        }
        BUFFER_FIL_CHAR(buffer, buffer_max, offset, '|');
        BUFFER_FIL_CHAR(buffer, buffer_max, offset, '\n');
    }

    return offset;
}

static int network_pkt_show_tail(char *buffer, int buffer_max, int offset, int split_line_len) {
    int i = 0;
    for (i = 0; i < split_line_len; i++) {
        BUFFER_FIL_CHAR(buffer, buffer_max, offset, '-');
    }
    BUFFER_FIL_CHAR(buffer, buffer_max, offset, '\n');
    return offset;
}

static void network_pkt_show(struct pcap_pkthdr *pkt_header, const u_char *pkt_data, const struct iphdr *ipv4_hdr) {
    assert(pkt_header);
    assert(pkt_data);
    
    apr_size_t byte_max = 20;
    char buffer[1024] = {'\0'};
    apr_size_t max = sizeof(buffer) - 2;
    int offset = 0;
    if (offset + 2 < max) {
        buffer[offset++] = '\n';
        buffer[offset++] = '\n';
    }
    int split_line_len = 0;
    offset = network_pkt_show_head(buffer, max, offset, byte_max, &split_line_len);
    offset = network_pkt_show_body(buffer, max, offset, byte_max, ipv4_hdr, pkt_data, pkt_header->caplen);
    offset = network_pkt_show_tail(buffer, max, offset, split_line_len);
    buffer[offset] = '\0';
    SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "%.*s", offset, buffer);
}

static apr_status_t network_pkt_get(network_pkt_t *pkt, int offset_to_ip, struct pcap_pkthdr *pkt_header, const u_char *pkt_data, unsigned long long pkt_index) {
    assert(pkt);

    if (!pkt_header || !pkt_data) {
        return APR_BADARG;
    }

    const struct iphdr *ip_hdr = NULL;
    if (offset_to_ip == sizeof(struct ethhdr)) {
        ip_hdr = sipdump_network_ip_get(pkt_data);
    } else {
        ip_hdr = (struct iphdr *)((char*)pkt_data + offset_to_ip);
    }
    if (!ip_hdr) {
        return APR_BADARG;
    }

    const struct iphdr *ipv4_hdr = sipdump_network_tunnel_ip_skip(ip_hdr);
    if (!ipv4_hdr) {
        return APR_ENOTIMPL;
    }

    if (sipdump_log_priority_trace()) {
        network_pkt_show(pkt_header, pkt_data, ipv4_hdr);
    }

    const struct tcphdr *tcp_hdr = NULL;
    const struct udphdr *udp_hdr = NULL;
    const char *data = NULL;
    
    pkt->pkt_header = pkt_header;
    pkt->pkt_data = pkt_data;
    pkt->version = ipv4_hdr->version;
    pkt->timestamp = apr_time_make(pkt_header->ts.tv_sec, pkt_header->ts.tv_usec);

    switch (ipv4_hdr->version) {
        case IPVERSION: {
            const char *tup = (char*)ipv4_hdr + sizeof(struct iphdr);
            pkt->ipv4 = ipv4_hdr;
            pkt->socket_pair.protocol = ipv4_hdr->protocol;
            pkt->socket_pair.version = ipv4_hdr->version;
            tcp_hdr = (const struct tcphdr *)tup;
            udp_hdr = (const struct udphdr *)tup;
            pkt->udp = udp_hdr;
            pkt->tcp = tcp_hdr;
            pkt->socket_pair.src.ip = ipv4_hdr->saddr;
            pkt->socket_pair.dst.ip = ipv4_hdr->daddr;

            u_int16_t frag_off = htons(pkt->ipv4->frag_off);
            uint16_t fragment = (frag_off & 0xE000) >> 13;
            pkt->fragment.DF = fragment & 0x02;
            pkt->fragment.MF = fragment & 0x01;
            pkt->offset = (frag_off & 0x1FFF) << 3;

            switch (ipv4_hdr->protocol) {
                case IPPROTO_UDP: {
                    if (pkt->offset) {
                        data = (const char*)tup;
                        pkt->total = htons(ipv4_hdr->tot_len) - sizeof(struct iphdr);
                    } else {
                        data = (const char*)((char*)udp_hdr + sizeof(struct udphdr));
                        pkt->socket_pair.src.port = htons(udp_hdr->source);
                        pkt->socket_pair.dst.port = htons(udp_hdr->dest);
                        pkt->total = htons(udp_hdr->len);
                    }
                    break;
                }

                case IPPROTO_ICMP: {
                    apr_status_t status = network_pkt_get(pkt, 0, pkt_header, tup + sizeof(struct icmphdr), pkt_index);
                    if (status == APR_SUCCESS) {
                        pkt->socket_pair.protocol = IPPROTO_ICMP;
                    }
                    break;
                }

                case IPPROTO_TCP: {
                    data = (const char *)((char *)tcp_hdr + (tcp_hdr->doff  *4));
                    pkt->socket_pair.src.port = htons(tcp_hdr->source);
                    pkt->socket_pair.dst.port = htons(tcp_hdr->dest);
                    break;
                }
                
                default:
                    // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "Unknown network protocol: %d", ipv4_hdr->protocol);
                    return APR_ENOTIMPL;
            }
            break;
        }

#ifdef SIPUDMP_HAVE_IPV6
        case 6: {
            const struct ip6_hdr *ipv6_hdr = (const struct ip6_hdr*)ipv4_hdr;
            pkt->ipv6 = ipv6_hdr;
            const char *tup = ((char*)ipv4_hdr + sizeof(struct ip6_hdr) + (ipv6_hdr->ip6_nxt == IPPROTO_FRAGMENT ? 8 : 0));
            tcp_hdr = (const struct tcphdr *)tup;
            udp_hdr = (const struct udphdr *)tup;
            pkt->udp = udp_hdr;
            pkt->tcp = tcp_hdr;
            pkt->socket_pair.version = ipv4_hdr->version;
            pkt->socket_pair.src.ip = ipv6_hdr->ip6_src.s6_addr32[0] + ipv6_hdr->ip6_src.s6_addr32[1]  *19 + ipv6_hdr->ip6_src.s6_addr32[2]  *37 + ipv6_hdr->ip6_src.s6_addr32[3]  *109;
            pkt->socket_pair.dst.ip = ipv6_hdr->ip6_dst.s6_addr32[0] + ipv6_hdr->ip6_dst.s6_addr32[1]  *19 + ipv6_hdr->ip6_dst.s6_addr32[2]  *37 + ipv6_hdr->ip6_dst.s6_addr32[3]  *109;
            switch (ipv6_hdr->ip6_nxt) {
                case IPPROTO_UDP: {
                    pkt->socket_pair.protocol = ipv6_hdr->ip6_nxt;
                    data = (const char*)((char*)udp_hdr + sizeof(struct udphdr));
                    pkt->socket_pair.src.port = htons(udp_hdr->source);
                    pkt->socket_pair.dst.port = htons(udp_hdr->dest);
                    break;
                }

                case IPPROTO_FRAGMENT: {
                    if (((char*)ipv6_hdr)[40] == IPPROTO_UDP) {
                        pkt->socket_pair.protocol = IPPROTO_UDP;
                        data = (const char*)((char*)udp_hdr + sizeof(struct udphdr));
                        pkt->socket_pair.src.port = htons(udp_hdr->source);
                        pkt->socket_pair.dst.port = htons(udp_hdr->dest);
                    } else if (((char*)ipv6_hdr)[40] == IPPROTO_TCP) {
                        pkt->socket_pair.protocol = IPPROTO_TCP;
                        data = (const char *)((char *)tcp_hdr + (tcp_hdr->doff  *4));
                        pkt->socket_pair.src.port = htons(tcp_hdr->source);
                        pkt->socket_pair.dst.port = htons(tcp_hdr->dest);
                    }
                    break;
                }
                
                default:
                    // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "Unknown network protocol: %d", ipv6_hdr->ip6_nxt);
                    return APR_ENOTIMPL;
            }
            break;
        }
#endif
        
        default:
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "PCAP Unknown network version: %d", ipv4_hdr->version);
            return APR_ENOTIMPL;
    }

    if (data) {
        apr_size_t size = MIN(pkt_header->len, pkt_header->caplen) - (unsigned long)((char*)data - (char*)pkt_data);
        pkt->data = data; 
        pkt->size = size;
    }

    if (sipdump_log_priority_trace()) {
        char describe[128] = {'\0'};
        if (pkt->fragment.MF) {
            snprintf(describe, sizeof(describe), 
                "More fragments(id: 0x%04X) total: %u", pkt->ipv4->id, pkt->total);
        } else if (!pkt->fragment.MF && pkt->offset) {
            snprintf(describe, sizeof(describe), 
                "End fragments(id: 0x%04X) offset: %u", pkt->ipv4->id, pkt->offset);
        }
        SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "PCAP pkt. #%lu.%lu %lu 0x%08X:%-5u -> 0x%08X:%-5u %-5s [D@%-4u:C@%-4u:L@%-4u] %s", 
            pkt_index,
            pkt_header->ts.tv_sec, pkt_header->ts.tv_usec,
            pkt->socket_pair.src.ip, pkt->socket_pair.src.port, 
            pkt->socket_pair.dst.ip, pkt->socket_pair.dst.port,
            sipdump_network_protocol_str(pkt->socket_pair.protocol), 
            pkt->size, pkt_header->caplen, pkt_header->len, describe
        );
    }
    return APR_SUCCESS;
}

static apr_status_t network_pkt_sip_proc(network_pkt_t *pkt, sipdump_pcap_t *pcap, sipdump_session_t **session, network_pkt_type_e *pkt_type) {
    assert(pkt);
    assert(pcap);
    assert(session);
    assert(pkt_type);
    
    /** 解析SIP起始行 */
    sipdump_sip_method_e sip_method = SIPDUMP_SIP_METHOD_UNKNOWN;
    const char *sip_method_name = NULL;
    sipdump_sip_code sip_code = 0;
    apr_status_t status = sipdump_sip_start_line_get(pkt->data, pkt->size, &sip_method, &sip_method_name, &sip_code);
    if (status != APR_SUCCESS) {
        return status;
    }
    *pkt_type = SIPDUMP_PKT_TYPE_SIP;

    /** 解析SIP */
    sipdump_sip_t sip;
    memset(&sip, 0, sizeof(sipdump_sip_t));
    status = sipdump_sip_parse(pkt->data, pkt->size, sip_method, sip_code, &sip);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP SIP parse error: %d", status); 
        return status;
    }

    /** 根据Call-ID找会话 */
    const sipdump_string_t *call_id = sipdump_sip_call_id_get(&sip);
    if (!call_id) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP SIP Call-ID get error"); 
        return APR_BADARG;
    }

    sipdump_session_t *s = sipdump_session_sip_find(call_id);
    if (!s) {
        /** 方法是否被过滤 */
        if (sip_method != SIPDUMP_SIP_METHOD_UNKNOWN) {
            int ret = sipdump_opt_sip_method_filter_test(pcap->opt, sip_method);
            if (!ret) {
                SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "PCAP SIP request method: %d(%s) has filtered", sip_method, sip_method_name); 
                return APR_EACCES;
            }
        }
        
        /** 是否符合创建会话条件 */
        int ret = sipdump_sip_create_session_method_test(sip_method);
        if (!ret) {
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "PCAP SIP method: %s(%d), Code: %u can't create session", 
                sip_method_name, sip_method, sip_code); 
            return APR_EACCES;
        }
        
        /** 创建会话 */
        status = sipdump_session_create(&s, pkt, pcap->opt, pcap->handle, &sip);
        if (status != APR_SUCCESS) {
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP create session error: %d", status); 
            return status;
        }

        /** 关联Call-ID和会话 */
        sipdump_session_sip_padding(s, &pkt->socket_pair);
    }

    *session = s;

    sipdump_session_pkt_save(s, pkt->pkt_header, pkt->pkt_data, *pkt_type);

    if (sip_method != SIPDUMP_SIP_METHOD_UNKNOWN) {
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s SIP Method: %s, CSeq: %u %s"
#ifndef SIPDUMP_USE_CALLID_AS_UUID
            ", Call-ID: %.*s"
#endif
            , 
            sipdump_session_uuid_get(s),
            sip_method_name, 
            sip.hdr.cseq.seq, sip.hdr.cseq.method_name, 
#ifndef SIPDUMP_USE_CALLID_AS_UUID
            sip.hdr.call_id.len, sip.hdr.call_id.str,
#endif
            ""
        );
    } else {
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s SIP Code: %d, CSeq: %u %s"
#ifndef SIPDUMP_USE_CALLID_AS_UUID
            ", Call-ID: %.*s"
#endif
            , 
            sipdump_session_uuid_get(s),
            sip_code, 
            sip.hdr.cseq.seq, sip.hdr.cseq.method_name,
#ifndef SIPDUMP_USE_CALLID_AS_UUID
            sip.hdr.call_id.len, sip.hdr.call_id.str,
#endif      
            ""
        );
    }

    /** 分片包，延迟解析 */
    if (pkt->fragment.MF) {
        return APR_ENOTENOUGHENTROPY;
    }

    sipdump_plugins_hook_sip_message_do(s, sip_method, sip_code, sip.hdr.hdrs, sip.hdr.count, pkt->data, pkt->size);

    if (sip.sdp.has) {
        status = sipdump_sdp_parse(pkt->data, pkt->size, sipdump_session_pool_get(s), &sip.sdp, sip.hdr.content_length);
        if (status != APR_SUCCESS) {
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "%s SDP parse error: %d", 
                sipdump_session_uuid_get(s), status); 
            return status;
        }

        char audio_rtp_addr[48] = {'\0'};
        char audio_rtcp_addr[48] = {'\0'};
#ifndef SIPDUMP_MRCP
        char video_rtp_addr[48] = {'\0'};
        char video_rtcp_addr[48] = {'\0'};
#else
        char mrcp_addr[48] = {'\0'};
#endif
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s SDP "
            "AUDIO [RTP: %s RTCP: %s] "
#ifndef SIPDUMP_MRCP
            "VIDEO [RTP: %s RTCP: %s] "
#else
            "MRCP  [CTRL: %s]"
#endif
            , 
            sipdump_session_uuid_get(s),
            sipdump_network_socket_str(IPVERSION, &sip.sdp.audio_rtp, audio_rtp_addr, sizeof(audio_rtp_addr)),
            sipdump_network_socket_str(IPVERSION, &sip.sdp.audio_rtcp, audio_rtcp_addr, sizeof(audio_rtcp_addr)),
#ifndef SIPDUMP_MRCP
            sipdump_network_socket_str(IPVERSION, &sip.sdp.video_rtp, video_rtp_addr, sizeof(video_rtp_addr)),
            sipdump_network_socket_str(IPVERSION, &sip.sdp.video_rtcp, video_rtcp_addr, sizeof(video_rtcp_addr)),
#else
            sipdump_network_socket_str(IPVERSION, &sip.sdp.mrcp.media, mrcp_addr, sizeof(mrcp_addr)),
#endif
            ""
        ); 

        /** 记录SDP */
        status = sipdump_session_sip_sdp_padding(s, &sip.sdp);
        if (status != APR_SUCCESS) {
            if (status == APR_EINPROGRESS) {
                SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s SDP re-transmission or proxy-transmission", 
                    sipdump_session_uuid_get(s)); 
            } else {
                SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "%s SDP padding to session error: %d", 
                    sipdump_session_uuid_get(s), status); 
            }
            return status;
        }
    }

    /** 会话终止 */
    if (sip_code && sip.hdr.cseq.method == SIPDUMP_SIP_METHOD_BYE) {
        /** 收到BYE的响应消息 */
        sipdump_session_terminating(s, pkt, TRUE);
        *session = NULL;
    } else if (400 <= sip_code && sip_code < 700 && sip_code != 407 && sip.hdr.cseq.method == SIPDUMP_SIP_METHOD_INVITE) {
        /** 收到错误响应 */
        sipdump_session_terminating(s, pkt, FALSE);
        sipdump_session_last_ack_wait_set(s);
    } else if (sip_method == SIPDUMP_SIP_METHOD_ACK && sipdump_session_last_ack_wait_get(s)) {
        /** 收到最终应答ACK */
        sipdump_session_terminating(s, pkt, TRUE);
        *session = NULL;
    } else if (sip_method == SIPDUMP_SIP_METHOD_CANCEL || sip_method == SIPDUMP_SIP_METHOD_BYE) {
        /** 收到CANCEL或者BYE请求 */
        sipdump_session_terminating(s, pkt, FALSE);
    }

    return APR_SUCCESS;
}
#ifdef SIPDUMP_MRCP
static apr_status_t network_pkt_mrcp_proc(network_pkt_t *pkt, sipdump_pcap_t *pcap, sipdump_session_t **session, network_pkt_type_e *pkt_type) {
    assert(pkt);
    assert(pcap);
    assert(session);
    assert(pkt_type);

    // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "\nPCAP MRCP data: %.*s", pkt->size, pkt->data); 
    
    sipdump_mrcp_t *mrcp = NULL;
    apr_status_t status = sipdump_mrcp_parse(pkt->data, pkt->size, &mrcp);
    if (status != APR_SUCCESS) {
        // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "PCAP MRCP parse error. code: %d", status); 
        return status;
    }

    sipdump_string_t hdr = { "Channel-Identifier", sizeof("Channel-Identifier") - 1 };
    const sipdump_string_t *channel_id = sipdump_mrcp_hdr_get(mrcp, &hdr);
    if (!channel_id) {
        sipdump_mrcp_free(mrcp);
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP get MRCP Channel-Identifier error"); 
        return APR_BADARG;
    }

    *pkt_type = SIPDUMP_PKT_TYPE_MRCP;
    sipdump_session_t *s = sipdump_session_mrcp_find(channel_id);
    if (!s) {
        sipdump_mrcp_free(mrcp);
        SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "PCAP MRCP channel: %.*s(%u) not found", channel_id->len, channel_id->str, channel_id->len); 
        return APR_NOTFOUND; 
    }

    sipdump_plugins_hook_mrcp_message_do(
        s,
        sipdump_mrcp_message_type_get(mrcp),
        sipdump_mrcp_request_get(mrcp),
        sipdump_mrcp_request_state_get(mrcp),
        sipdump_mrcp_event_get(mrcp),
        sipdump_mrcp_code_get(mrcp),
        sipdump_mrcp_hdrs_get(mrcp),
        pkt->data, 
        pkt->size
    );

    sipdump_mrcp_show_message(mrcp, sipdump_session_uuid_get(s));
    sipdump_session_mrcp_padding(s, &pkt->socket_pair, mrcp);
    sipdump_session_pkt_save(s, pkt->pkt_header, pkt->pkt_data, *pkt_type);
    sipdump_mrcp_free(mrcp);

    *session = s;
    return APR_SUCCESS;
}
#endif

static apr_status_t network_pkt_idle(network_pkt_t *pkt, sipdump_pcap_t *pcap) {
    assert(pcap);
    return sipdump_session_zombie_kill(pkt);
}

static apr_status_t network_pkt_proc(network_pkt_t *pkt, sipdump_pcap_t *pcap) {
    assert(pkt);
    assert(pcap);

    /** 会话处理 */
    network_pkt_type_e pkt_type = SIPDUMP_PKT_TYPE_UNKNOWN;
    sipdump_session_t *session = sipdump_session_pkt_find(&pkt->socket_pair, &pkt_type);
    if (session) {
        SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "%s PCAP Found session, pkt type: %d", sipdump_session_uuid_get(session), pkt_type); 
        sipdump_session_pkt_save(session, pkt->pkt_header, pkt->pkt_data, pkt_type);
        return APR_SUCCESS;
    }

    SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "PCAP No session in pkt"); 
    apr_status_t status = network_pkt_sip_proc(pkt, pcap, &session, &pkt_type);
    switch (status) {
        case APR_SUCCESS:
        case APR_ENOTENOUGHENTROPY:
            break;
        
        default:
            #ifdef SIPDUMP_MRCP
                if (pkt_type == SIPDUMP_PKT_TYPE_UNKNOWN)  {
                    status = network_pkt_mrcp_proc(pkt, pcap, &session, &pkt_type);
                }
            #endif
            break;
    }

    return APR_SUCCESS;
}


static void *APR_THREAD_FUNC _pcap_run(apr_thread_t *thread, void *arg) {
    assert(thread);
    assert(arg);

    sipdump_pcap_t *pcap = (sipdump_pcap_t*)arg;
    unsigned long long pkt_index = 0;
    long int idle_time = 0;

    /** 标记线程已经启动，并且通知上层 */
    SIPDUMP_LOG(SIPDUMP_PRIO_NOTICE, "PCAP thread is running");
    apr_thread_mutex_lock(pcap->mutex);
    pcap->running = TRUE;
    apr_thread_cond_signal(pcap->cond);
    apr_thread_mutex_unlock(pcap->mutex);
    
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP eth hdr length: %u", sizeof(struct ethhdr));
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP ip  hdr length: %u", sizeof(struct iphdr));
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP udp hdr length: %u", sizeof(struct udphdr));
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "PCAP tcp hdr length: %u", sizeof(struct tcphdr));

    do {
        /** 抓包 */
        struct pcap_pkthdr *pkt_header; 
        const u_char *pkt_data;
        int ret = pcap_next_ex(pcap->handle, &pkt_header, &pkt_data);
        if (ret < 0) {
            break;
        } else if (ret == 0) {
            continue;
        }
        pkt_index++;
        /** 从网络包中解析关键数据 */
        network_pkt_t pkt;
        memset(&pkt, 0, sizeof(network_pkt_t));
        apr_status_t status = network_pkt_get(&pkt, pcap->offset_to_ip, pkt_header, pkt_data, pkt_index);
        if (status != APR_SUCCESS) {
            // SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP pkt get error. status: %d [%u %u]", status, pkt_header->caplen, pkt_header->len); 
            continue;
        }

        // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "PCAP pkt time: %llu.%llu\n", pkt_header->ts.tv_sec, pkt_header->ts.tv_usec);

        /** 处理数据 */
        if (pkt.data && pkt.size) { 
            apr_status_t status = sipdump_fragment_cache(&pkt);
            switch (status) {
            case APR_SUCCESS:
            case APR_ENOTENOUGHENTROPY:
                network_pkt_proc(&pkt, pcap);
                break;

            default:
                // SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "PCAP pkt get error. status: %d [%u %u]", status, pkt_header->caplen, pkt_header->len); 
                break;
            }
        }

        /** 检查 */
        if (pkt_header->ts.tv_sec - idle_time > 30) {
            idle_time = pkt_header->ts.tv_sec;
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "PCAP is time to idle. now: %lu.%lu", 
                pkt_header->ts.tv_sec, pkt_header->ts.tv_usec); 
            network_pkt_idle(&pkt, pcap);
        }
    } while(pcap->running);

    /** 线程退出 */
    apr_thread_exit(thread, APR_SUCCESS);
    SIPDUMP_LOG(SIPDUMP_PRIO_NOTICE, "PCAP thread is exiting");

    return NULL;
}