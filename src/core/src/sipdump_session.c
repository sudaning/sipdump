#include <assert.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_hash.h>
#include <apr_uuid.h>
#include <apr_ring.h>
#include <apr_file_io.h>

#include <pcap.h>

#include "sipdump_config.h"
#include "sipdump_util.h"
#include "sipdump_plugins.h"
#include "sipdump_log.h"
#include "sipdump_opt.h"
#include "sipdump_network.h"
#include "sipdump_session.h"

#define ADDR_RELATION_HASH_KEY_MAX (2  *IPGROUP_MAX_IP)

struct sipdump_addr_relation_item_t {
    struct network_socket_pair socket_pair;
    sipdump_string_t hash_key[ADDR_RELATION_HASH_KEY_MAX];
    uint32_t hash_key_count;
};
typedef struct sipdump_addr_relation_item_t sipdump_addr_relation_item_t;

struct sipdump_addr_relation_t {
    sipdump_addr_relation_item_t audio_rtp;
    sipdump_addr_relation_item_t audio_rtcp;

    sipdump_addr_relation_item_t video_rtp;
    sipdump_addr_relation_item_t video_rtcp;
#ifdef SIPDUMP_MRCP
    sipdump_addr_relation_item_t mrcp;
#endif
};
typedef struct sipdump_addr_relation_t sipdump_addr_relation_t;

struct sipdump_session_t {

    APR_RING_ENTRY(sipdump_session_t) link;

    void* plugin_user_data;

    apr_pool_t *pool; /** 内存池 */
    char *uuid;
    struct {
        apr_time_t created;
        apr_time_t terminating;
        apr_time_t destroyed;
        apr_time_t limited;
    } time;

    sipdump_opt_t *opt;

    /** 写文件的目录 */
    const char *record_dir;

    /** PCAP */
    pcap_t *pcap_handle;
    const char *pcap_file_path;
    const char *pcap_file_suffix;
    pcap_dumper_t *pcap_dumper;
    int pcap_flush;
    unsigned int pcap_pkt_cnt[SIPDUMP_PKT_TYPE_MAX];

    /** Info */
    const char *info_file_path;
    const char *info_file_suffix;

    /** SIP */
    struct {
        struct network_socket_pair socket;
        sipdump_string_t call_id;
        sipdump_string_t from_number;
        sipdump_string_t to_number;
        apr_hash_t* hdrs;
        int last_ack_wait; /** 等待最后的ack字段 */
    } sip;

    /** SDP */
    sipdump_sdp_t sdp[2]; /** 两个SDP offer和answer */

#ifdef SIPDUMP_MRCP
    /** MRCP */
    struct {
        sipdump_string_t channel_id;
        apr_hash_t *hdrs;
    } mrcp;
#endif

    /** 地址关系 */
    sipdump_addr_relation_t addr_relation;
};

typedef struct sipdump_session_mgr_t {
    apr_pool_t *pool;
    apr_hash_t *hash_sip_id; /** 通过SIP Call-ID找会话 */
#ifdef SIPDUMP_MRCP
    apr_hash_t *hash_mrcp_id; /** 通过MRCP Channel-Identifier找会话 */
#endif
    apr_hash_t *hash_rtp_addr; /** 通过RTP 地址信息找会话 */
    apr_size_t session_count;
    APR_RING_HEAD(sipdump_session_list_t, sipdump_session_t) sessions;
} sipdump_session_mgr_t;
static sipdump_session_mgr_t *session_mgr = NULL;

apr_status_t sipdump_session_init() {
    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, NULL);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "create pool error: %d", status);
        return status;
    }

    sipdump_session_mgr_t *mgr = apr_pcalloc(pool, sizeof(sipdump_session_mgr_t));
    if (!mgr) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "pcalloc from pool error");
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }
    mgr->pool = pool;

    mgr->hash_sip_id = apr_hash_make(pool);
#ifdef SIPDUMP_MRCP
    mgr->hash_mrcp_id = apr_hash_make(pool);
#endif
    mgr->hash_rtp_addr = apr_hash_make(pool);
    mgr->session_count = 0;

    APR_RING_INIT(&mgr->sessions, sipdump_session_t, link);

    if (!mgr->hash_sip_id 
#ifdef SIPDUMP_MRCP
        || !mgr->hash_mrcp_id 
#endif
        || !mgr->hash_rtp_addr
    ) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "make hash from pool error");
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }

    session_mgr = mgr;
    return APR_SUCCESS;
}

apr_status_t sipdump_session_uninit() {
    
    sipdump_session_mgr_t *mgr = session_mgr;
    if (!mgr) {
        return APR_SUCCESS;
    }

    sipdump_session_t *session = NULL;
    sipdump_session_t *next = NULL;
    APR_RING_FOREACH_SAFE(session, next, &mgr->sessions, sipdump_session_t, link) {
        sipdump_session_destroy(session, NULL);
    }

    if (mgr->pool) { 
        apr_pool_destroy(mgr->pool);
    }
    
    session_mgr = NULL;
    return APR_SUCCESS;
}

static void socket_network_addr_hash(uint8_t protocol, const struct network_addr *addr, sipdump_string_t *key) {
    assert(addr);
    assert(key);

    key->len = snprintf(key->str, key->len, "%u:0x%08X:%u", 
        protocol, addr->ip, addr->port);
    return;
}

static void socket_pair_phash(const struct network_socket_pair *socket_pair, apr_pool_t *pool, sipdump_string_t *key1, sipdump_string_t *key2) {
    assert(socket_pair);
    assert(pool);
    assert(key1);
    assert(key2);

    key1->str = apr_palloc(pool, 64);
    key1->len = 64;

    key2->str = apr_palloc(pool, 64);
    key2->len = 64;

    socket_network_addr_hash(socket_pair->protocol, &socket_pair->src, key1);
    socket_network_addr_hash(socket_pair->protocol, &socket_pair->dst, key2);

    return;
}


static void relation_clear(apr_hash_t *hash, sipdump_session_t *session, sipdump_string_t *key, const char *tag) {
    assert(hash);
    assert(session);
    assert(key);

    if (key->len) {
        apr_hash_set(hash, key->str, key->len, NULL);
        SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "%s [-] Relation(%s) %.*s hash: 0x%08X" , 
            session->uuid, tag, key->len, key->str, (void*)hash);
    }
    return;
} 


static void relation_build(apr_hash_t *hash, sipdump_session_t *session, sipdump_string_t *key, const char *tag) {
    assert(hash);
    assert(session);
    assert(key);

    if (key->len) {
        apr_hash_set(hash, key->str, key->len, session);
        SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "%s [+] Relation(%s) %.*s -> 0x%08X hash: 0x%08X" , 
            session->uuid, tag, key->len, key->str, session, (void*)hash);
    }
    return;
} 

static void relation_addr_build(apr_hash_t *hash, sipdump_session_t *session, sipdump_addr_relation_item_t *item, const char *tag) {
    assert(hash);
    assert(session);
    assert(item);

    if (!item->socket_pair.src.ip || !item->socket_pair.src.port || !item->socket_pair.dst.ip || !item->socket_pair.dst.port) {
        return;
    }

    struct network_addr *addrs[2] = {
        &item->socket_pair.src,
        &item->socket_pair.dst,
    };

    int m = 0;
    sipdump_string_t *hash_key = &item->hash_key[item->hash_key_count];
    for (m = 0; m < sipdump_arraylen(addrs); m++) {
        const sipdump_ipgroup_item_t *ip_group = NULL;
        struct network_addr *addr = addrs[m];
        apr_status_t rv = sipdump_opt_ipgroup_get(session->opt, addr->ip, &ip_group);
        if (rv == APR_SUCCESS) {
            char ip_buffer[32] = {'\0'};
            sipdump_network_ntop(4, addr->ip, ip_buffer, sizeof(ip_buffer));
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "%s IP %s(0x%08X) in group '%s'", session->uuid, ip_buffer, addr->ip, ip_group->name);
            int i = 0;
            for (i = 0; i < ip_group->count; i++) {
                struct network_addr newaddr;
                newaddr.ip = ip_group->ips[i];
                newaddr.port = addr->port;
                char ip_buffer[32] = {'\0'};
                sipdump_network_ntop(4, newaddr.ip, ip_buffer, sizeof(ip_buffer));
                SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "%s IP group %s -> %s(0x%08X)", session->uuid, ip_group->name, ip_buffer, newaddr.ip);
                if (item->hash_key_count >= ADDR_RELATION_HASH_KEY_MAX) {
                    break;
                }
                hash_key->len = 64;
                hash_key->str = apr_pcalloc(session->pool, hash_key->len);
                socket_network_addr_hash(item->socket_pair.protocol, &newaddr, hash_key);
                relation_build(hash, session, hash_key, tag);
                hash_key = &item->hash_key[item->hash_key_count++];
                
            }
        } else {
            if (item->hash_key_count >= ADDR_RELATION_HASH_KEY_MAX) {
                break;
            }
            hash_key->len = 64;
            hash_key->str = apr_pcalloc(session->pool, hash_key->len);
            socket_network_addr_hash(item->socket_pair.protocol, addr, hash_key);
            relation_build(hash, session, hash_key, tag);
            hash_key = &item->hash_key[item->hash_key_count++];
        }
    }
    
    return;
} 

static void relation_addr_clear(apr_hash_t *hash, sipdump_session_t *session, sipdump_addr_relation_item_t *item, const char *tag) {
    assert(hash);
    assert(session);
    assert(item);

    int i = 0;
    for (i = 0; i < item->hash_key_count; i++) {
        relation_clear(hash, session, &item->hash_key[i], tag);
    }
    return;
} 

static apr_status_t relation_addr_from_sdp(sipdump_addr_relation_item_t *item, uint8_t protocol, struct network_addr *media1, struct network_addr *media2) {
    assert(item);
    assert(media1);
    assert(media2);
    item->socket_pair.protocol = protocol;
    item->socket_pair.src.ip = media1->ip;
    item->socket_pair.src.port = media1->port;
    item->socket_pair.dst.ip = media2->ip;
    item->socket_pair.dst.port = media2->port;
    return APR_SUCCESS;
}

#define SIPDUMP_RECORD_PATH_MAX 256
static apr_status_t sipdump_session_record_path_format(char **path, const char *format, apr_time_exp_t *time, sipdump_session_t *session) {
    assert(path);
    assert(session);
    assert(format);

    char *buffer = apr_pcalloc(session->pool, SIPDUMP_RECORD_PATH_MAX);
    int buffer_len = 0;
    const char *tmp = format;

    int token_in = FALSE;
    const char *token_start = NULL;
    char token[32] = {'\0'};
    while(*tmp) {
        if (!token_in && *tmp == '$' && *(tmp + 1) == '{') {
            token_in = TRUE;
            tmp += 2;
            token_start = tmp;
            continue;
        } else if (token_in && *tmp == '}') {
            memset(token, 0, sizeof(token));
            strncpy(token, token_start, tmp - token_start);
            int len = 0;
            // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "token: %s, buffer: 0x%08X, len: %u", token, buffer, buffer_len);
            if (!strcmp(token, "year")) {
                buffer_len += snprintf(buffer + buffer_len, SIPDUMP_RECORD_PATH_MAX - buffer_len, "%04u", time->tm_year + 1900);
            } else if (!strcmp(token, "month")) {
                buffer_len += snprintf(buffer + buffer_len, SIPDUMP_RECORD_PATH_MAX - buffer_len, "%02u", time->tm_mon + 1);
            } else if (!strcmp(token, "day")) {
                buffer_len += snprintf(buffer + buffer_len, SIPDUMP_RECORD_PATH_MAX - buffer_len, "%02u", time->tm_mday);
            } else if (!strcmp(token, "hour")) {
                buffer_len += snprintf(buffer + buffer_len, SIPDUMP_RECORD_PATH_MAX - buffer_len, "%02u", time->tm_hour);
            } else if (!strcmp(token, "minute")) {
                buffer_len += snprintf(buffer + buffer_len, SIPDUMP_RECORD_PATH_MAX - buffer_len, "%02u", time->tm_min);
            } else if (!strcmp(token, "second")) {
                buffer_len += snprintf(buffer + buffer_len, SIPDUMP_RECORD_PATH_MAX - buffer_len, "%02u", time->tm_sec);
            } else if (!strcmp(token, "usecond")) {
                buffer_len += snprintf(buffer + buffer_len, SIPDUMP_RECORD_PATH_MAX - buffer_len, "%06u", time->tm_usec);
            } else if (!strcmp(token, "sip_from_number")) {
                strncpy(buffer + buffer_len, session->sip.from_number.str, session->sip.from_number.len);
                buffer_len += session->sip.from_number.len;
            } else if (!strcmp(token, "sip_to_number")) {
                strncpy(buffer + buffer_len, session->sip.to_number.str, session->sip.to_number.len);
                buffer_len += session->sip.to_number.len;
            } else if (!strcmp(token, "sip_call_id")) {
                strncpy(buffer + buffer_len, session->sip.call_id.str, session->sip.call_id.len);
                buffer_len += session->sip.call_id.len;
            } else if (!strncmp(token, "sip_h_", sizeof("sip_h_") - 1)) {
                if (session->sip.hdrs) {
                    char *custom_hdr = token + sizeof("sip_h_") - 1;
                    const char *value = apr_hash_get(session->sip.hdrs, custom_hdr, APR_HASH_KEY_STRING);
                    if (value) {
                        buffer_len += snprintf(buffer + buffer_len, SIPDUMP_RECORD_PATH_MAX - buffer_len, "%s", value);
                    }
                }
            }
#ifdef SIPDUMP_MRCP
            else if (!strcmp(token, "mrcp_channel_id")) {
                strncpy(buffer + buffer_len, session->mrcp.channel_id.str, session->mrcp.channel_id.len);
                buffer_len += session->mrcp.channel_id.len;
            } else if (!strncmp(token, "mrcp_h_", sizeof("mrcp_h_") - 1)) {
                if (session->mrcp.hdrs) {
                    char *custom_hdr = token + sizeof("mrcp_h_") - 1;
                    const char *value = apr_hash_get(session->mrcp.hdrs, custom_hdr, APR_HASH_KEY_STRING);
                    if (value) {
                        buffer_len += snprintf(buffer + buffer_len, SIPDUMP_RECORD_PATH_MAX - buffer_len, "%s", value);
                    }
                }
            }
#endif
            token_in = FALSE;
            token_start = NULL;
        } else if (!token_in) {
            *(buffer + buffer_len) = *tmp;
            buffer_len++;
        } 
        tmp++;
    }

    *path = buffer;

    return APR_SUCCESS;
}

static apr_status_t sipdump_session_save_file(sipdump_session_t *session, sipdump_opt_t *opt) {
    apr_time_exp_t time_exp;
	apr_time_t now = apr_time_now();
	apr_time_exp_lt(&time_exp, now);

    char *path = NULL;
    const char *format = sipdump_opt_pcap_record_path_get(opt);
    apr_status_t status = sipdump_session_record_path_format(&path, format, &time_exp, session);
    if (status != APR_SUCCESS) {
        return status;
    }
    

    /** 目录 */
    char *rd = strrchr(path, '/');
    if (rd) {
        session->record_dir = apr_pstrndup(session->pool, path, rd - path);
        sipdump_mkdir(session->record_dir, 0777);
    } else {
        session->record_dir = ".";
    }

    /** 文件后缀 */
    char *suffix = strrchr(path, '.');
    if (suffix) {
        session->pcap_file_suffix = apr_pstrdup(session->pool, suffix + 1);
        session->pcap_file_path = path;
    } else {
        session->pcap_file_suffix = "pcap";
        session->pcap_file_path = apr_psprintf(session->pool, "%s.%s", path, session->pcap_file_suffix);
    }

    session->info_file_path = apr_psprintf(session->pool, "%s.%s", path, session->info_file_suffix);

    return APR_SUCCESS;
}

apr_status_t sipdump_session_create(sipdump_session_t **session, network_pkt_t *pkt, sipdump_opt_t *opt, pcap_t *pcap_handle, sipdump_sip_t *sip) {
    assert(session);
    assert(pcap_handle);

    sipdump_session_mgr_t *mgr = session_mgr;

#ifdef SIPUDMP_HAVE_ONLY_ONE_SESSION
    if (!APR_RING_EMPTY(&mgr->sessions, sipdump_session_t, link)) {
        return APR_EBUSY;
    }
#endif

    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, NULL);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "Create pool error: %d", status);
        return status;
    }

    sipdump_session_t *s = apr_pcalloc(pool, sizeof(sipdump_session_t));
    s->pool = pool;

    /** UUID */
#ifndef SIPDUMP_USE_CALLID_AS_UUID
    s->uuid = apr_pcalloc(pool, APR_UUID_FORMATTED_LENGTH + 1);
    apr_uuid_t uuid;
    apr_uuid_get(&uuid);
    apr_uuid_format(s->uuid, &uuid);
#else
    s->uuid = apr_pstrndup(s->pool, sip->hdr.call_id.str, sip->hdr.call_id.len);
    SIPDUMP_LOG(SIPDUMP_PRIO_DEBUG, "%s Use SIP Call-ID as uuid.", s->uuid);
#endif
    s->opt = opt;
    s->sip.call_id.str = apr_pstrndup(s->pool, sip->hdr.call_id.str, sip->hdr.call_id.len);
    s->sip.call_id.len = sip->hdr.call_id.len;
    s->sip.from_number.str = apr_pstrndup(s->pool, sip->hdr.from.user.str, sip->hdr.from.user.len);
    s->sip.from_number.len = sip->hdr.from.user.len;
    s->sip.to_number.str = apr_pstrndup(s->pool, sip->hdr.to.user.str, sip->hdr.to.user.len);
    s->sip.to_number.len = sip->hdr.to.user.len;

    if (sip->hdr.count) {
        s->sip.hdrs = apr_hash_make(s->pool);
        int i = 0;
        for (i = 0; i < sip->hdr.count; i++) {
            sipdump_sip_hdr_common_t *ext = &sip->hdr.hdrs[i];
            const char *key = apr_pstrndup(s->pool, ext->name.str, ext->name.len);
            const char *val = apr_pstrndup(s->pool, ext->value.str, ext->value.len);
            apr_hash_set(s->sip.hdrs, key, ext->name.len, val);
        }
    }
    s->sip.last_ack_wait = FALSE;

    /** 时间 */
    s->time.created = pkt->timestamp;
    s->time.terminating = 0;
    s->time.destroyed = 0;
    s->time.limited = s->time.created + sipdump_opt_limit_time_get(opt)  *APR_USEC_PER_SEC;

    s->info_file_suffix = "txt";

    /** PCAP数据保存路径 */
    status = sipdump_session_save_file(s, opt);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "%s Create file error. code: %d", s->uuid, status);
        return status;
    }
    s->pcap_dumper = pcap_dump_open(pcap_handle, s->pcap_file_path);
    if (!s->pcap_dumper) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "%s Open pcap dump error.", s->uuid);
        return APR_EINTR;
    }
    s->pcap_handle = pcap_handle;
    s->pcap_flush = sipdump_opt_pcap_flush_get(opt);


    /** 添加到环尾 */
    APR_RING_INSERT_TAIL(&mgr->sessions, s, sipdump_session_t, link);
    mgr->session_count++;

    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s Session created at %" APR_TIME_T_FMT ".%" APR_TIME_T_FMT 
        ", limit at %" APR_TIME_T_FMT ".%" APR_TIME_T_FMT ", remaining session: %u(s)", 
        s->uuid, 
        apr_time_sec(s->time.created), apr_time_usec(s->time.created),
        apr_time_sec(s->time.limited), apr_time_usec(s->time.limited), 
        mgr->session_count); 
    SIPDUMP_LOG(SIPDUMP_PRIO_DEBUG, "%s Saving the packet to '%s' by dumper: 0x%08X", 
        s->uuid, s->pcap_file_path, s->pcap_dumper);
    
    *session = s;
    return APR_SUCCESS;
}

static void sipdump_session_info(sipdump_session_t *session) {
    char create_time[64] = {'\0'};
    sipdump_timestamp_snprintf(session->time.created, create_time, sizeof(create_time));
 
    char limited_time[64] = {'\0'};
    sipdump_timestamp_snprintf(session->time.limited, limited_time, sizeof(limited_time));

    char terminating_time[64] = {'\0'};
    sipdump_timestamp_snprintf(session->time.terminating, terminating_time, sizeof(terminating_time));

    char destroy_time[64] = {'\0'};
    sipdump_timestamp_snprintf(session->time.destroyed, destroy_time, sizeof(destroy_time));

    char sip_socket[64] = {'\0'};

    char rtp_audio_socket[64] = {'\0'};
    char rtcp_audio_socket[64] = {'\0'};
    char rtp_video_socket[64] = {'\0'};
    char rtcp_video_socket[64] = {'\0'};
#ifdef SIPDUMP_MRCP
    char mrcp_socket[64] = {'\0'};
#endif
    char context[2048] = {'\0'};
    const char *plugin_context = sipdump_plugins_hook_session_print_do(session);

    apr_size_t context_len = (apr_size_t)snprintf(context, sizeof(context), "%s Session info: \n"
        "TIME Created:            %s\n"
        // "TIME Limited:            %s\n"
        "TIME Terminating:        %s\n"
        "TIME Destroyed:          %s\n"
        "PKT  COUNT SIP:          %u\n"
#ifdef SIPDUMP_MRCP
        "PKT  COUNT MRCP:         %u\n"
#endif
        "PKT  COUNT RTP:          %u\n"
        "PKT  COUNT RTCP:         %u\n"
        "PCAP File Path:          %s\n"
        "INFO File Path:          %s\n"
        "SIP  Call-ID:            %.*s\n"
        "SIP  Ctrl  Socket Addr:  %s\n"
        "RTP  Audio Socket Addr:  %s\n"
        "RTCP Audio Socket Addr:  %s\n"
#ifndef SIPDUMP_MRCP
        "RTP  Video Socket Addr:  %s\n"
        "RTCP Video Socket Addr:  %s\n"
#else
        "MRCP Ctrl  Socket Addr:          %s\n"
        "MRCP Channel-Identifier:         %.*s (%u)\n"
#endif
        "%s",
        session->uuid,
        create_time, 
        // limited_time,
        terminating_time, 
        destroy_time,
        session->pcap_pkt_cnt[SIPDUMP_PKT_TYPE_SIP], 
#ifdef SIPDUMP_MRCP
        session->pcap_pkt_cnt[SIPDUMP_PKT_TYPE_MRCP], 
#endif
        session->pcap_pkt_cnt[SIPDUMP_PKT_TYPE_RTP], 
        session->pcap_pkt_cnt[SIPDUMP_PKT_TYPE_RTCP],
        session->pcap_file_path,
        session->info_file_path,
        session->sip.call_id.len, session->sip.call_id.str,
        sipdump_network_socket_pair_str(&session->sip.socket, sip_socket, sizeof(sip_socket)), 
        sipdump_network_socket_pair_str(&session->addr_relation.audio_rtp.socket_pair, rtp_audio_socket, sizeof(rtp_audio_socket)),
        sipdump_network_socket_pair_str(&session->addr_relation.audio_rtcp.socket_pair, rtcp_audio_socket, sizeof(rtcp_audio_socket)),
#ifndef SIPDUMP_MRCP
        sipdump_network_socket_pair_str(&session->addr_relation.video_rtp.socket_pair, rtp_video_socket, sizeof(rtp_video_socket)),
        sipdump_network_socket_pair_str(&session->addr_relation.video_rtcp.socket_pair, rtcp_video_socket, sizeof(rtcp_video_socket)),
#else
        sipdump_network_socket_pair_str(&session->addr_relation.mrcp.socket_pair, mrcp_socket, sizeof(mrcp_socket)),
        session->mrcp.channel_id.len, session->mrcp.channel_id.str, session->mrcp.channel_id.len,
#endif
        plugin_context
    ); 

    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s", context);

    /** 会话信息总结性与统计输出到文件 */
    apr_file_t *info_file = NULL;
    apr_status_t status = apr_file_open(&info_file, session->info_file_path, APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_BINARY, APR_FPROT_OS_DEFAULT, session->pool);
    if (status != APR_SUCCESS) {
        return;
    }
    apr_file_write_full(info_file, context, context_len, NULL);
    apr_file_close(info_file);
}

apr_status_t sipdump_session_destroy(sipdump_session_t *session, network_pkt_t *pkt) {
    assert(session);

    sipdump_session_mgr_t *mgr = session_mgr;

    if (!session->time.destroyed) {
        session->time.destroyed = pkt ? pkt->timestamp : apr_time_now();
    }

    if (session->pcap_dumper) {
        pcap_dump_close(session->pcap_dumper);
    }

    /** record rename */
    const char *new_file_name = sipdump_plugins_hook_record_rename_do(session);
    if (new_file_name) {
        char *new_pcap_file_path = apr_psprintf(session->pool, "%s/%s.%s", session->record_dir, new_file_name, session->pcap_file_suffix);
        apr_file_rename(session->pcap_file_path, new_pcap_file_path, session->pool);
        session->pcap_file_path = new_pcap_file_path;
        SIPDUMP_LOG(SIPDUMP_PRIO_DEBUG, "%s Session rename pcap file: '%s'", session->uuid, session->pcap_file_path);

        char *new_info_file_path = apr_psprintf(session->pool, "%s/%s.%s", session->record_dir, new_file_name, session->info_file_suffix);
        session->info_file_path = new_info_file_path;
    }

    sipdump_session_info(session);

    /** 清除hash表 */
    /** SIP */
    relation_clear(mgr->hash_sip_id, session, &session->sip.call_id, "SIP@Call-ID");

#ifdef SIPDUMP_MRCP
    /** MRCP */
    relation_clear(mgr->hash_mrcp_id, session, &session->mrcp.channel_id, "MRCP@Chan-Id");
#endif
    /** RTP */
    relation_addr_clear(mgr->hash_rtp_addr, session, &session->addr_relation.audio_rtp, "RTP#a");
    relation_addr_clear(mgr->hash_rtp_addr, session, &session->addr_relation.audio_rtcp, "RTCP#a");
    relation_addr_clear(mgr->hash_rtp_addr, session, &session->addr_relation.video_rtp, "RTP#v");
    relation_addr_clear(mgr->hash_rtp_addr, session, &session->addr_relation.video_rtcp, "RTCP#v");

    APR_RING_REMOVE(session, link);
    mgr->session_count--;

    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s Session destroyed at %" APR_TIME_T_FMT ".%" APR_TIME_T_FMT 
        " remaining session: %u(s)", 
        session->uuid, 
        apr_time_sec(session->time.destroyed), apr_time_usec(session->time.destroyed),
        mgr->session_count); 

    if (session->pool) { 
        apr_pool_destroy(session->pool);
    }

    return APR_SUCCESS;
}

apr_status_t sipdump_session_zombie_kill(network_pkt_t *pkt) {
    apr_time_t now = pkt ? pkt->timestamp : apr_time_now();
    sipdump_session_mgr_t *mgr = session_mgr;
    sipdump_session_t *session = NULL;
    sipdump_session_t *next = NULL;
    APR_RING_FOREACH_SAFE(session, next, &mgr->sessions, sipdump_session_t, link) {
        if (session->time.terminating && now > session->time.terminating + 30  *APR_USEC_PER_SEC) {
            if (!session->time.destroyed) {
                SIPDUMP_LOG(SIPDUMP_PRIO_NOTICE, "%s Session is zombied (terminating timeout)", session->uuid); 
            } else {
                SIPDUMP_LOG(SIPDUMP_PRIO_NOTICE, "%s Session is destroying", session->uuid); 
            }
            sipdump_session_destroy(session, NULL);
        } else if (now > session->time.limited) {
            SIPDUMP_LOG(SIPDUMP_PRIO_NOTICE, "%s Session is zombied (limit timeout)", session->uuid); 
            sipdump_session_destroy(session, NULL);
        } else if ((!session->sdp[0].has || !session->sdp[1].has) && now > session->time.created + 120  *APR_USEC_PER_SEC) {
            SIPDUMP_LOG(SIPDUMP_PRIO_NOTICE, "%s Session is zombied (negotiate timeout)", session->uuid); 
            sipdump_session_destroy(session, NULL);
        }
    }
    
    return APR_SUCCESS;
}

apr_pool_t *sipdump_session_pool_get(sipdump_session_t *session) {
    assert(session);
    return session->pool;
}

void sipdump_session_plugin_user_data_set(sipdump_session_t *session, void* user_data) {
    assert(session);
    session->plugin_user_data = user_data;
}

void *sipdump_session_plugin_user_data_get(sipdump_session_t *session) {
    assert(session);
    return session->plugin_user_data;
}

apr_status_t sipdump_session_terminating(sipdump_session_t *session, network_pkt_t *pkt, int destroy){
    assert(session);

    if (!session->time.terminating) {
        session->time.terminating = pkt ? pkt->timestamp : apr_time_now();
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s Session terminating at %" APR_TIME_T_FMT ".%" APR_TIME_T_FMT,  
            session->uuid, 
            apr_time_sec(session->time.terminating), apr_time_usec(session->time.terminating)
        ); 
    }

    if (destroy && !session->time.destroyed) {
        session->time.destroyed = session->time.terminating;
    }
    return APR_SUCCESS;
}

const char *sipdump_session_uuid_get(sipdump_session_t *session) {
    assert(session);
    return session->uuid;
}

apr_status_t sipdump_session_last_ack_wait_set(sipdump_session_t *session) {
    assert(session);
    session->sip.last_ack_wait = TRUE;
    SIPDUMP_LOG(SIPDUMP_PRIO_DEBUG, "%s Session last ack wait", session->uuid); 
    return APR_SUCCESS;
}

int sipdump_session_last_ack_wait_get(sipdump_session_t *session) {
    assert(session);
    return session->sip.last_ack_wait;
}

unsigned int sipdump_session_pcap_pkt_count_get(sipdump_session_t *session, network_pkt_type_e pkt_type) {
    assert(session);
    if (SIPDUMP_PKT_TYPE_UNKNOWN < pkt_type && pkt_type < SIPDUMP_PKT_TYPE_MAX) {
        return session->pcap_pkt_cnt[pkt_type];
    }
    return 0;
}

sipdump_session_t *sipdump_session_pkt_find(const struct network_socket_pair *socket_pair, network_pkt_type_e *pkt_type) {
    assert(socket_pair);
    sipdump_session_mgr_t *mgr = session_mgr;

    sipdump_string_t key1;
    char tmp_key1[32] = {'\0'};
    key1.str = tmp_key1;
    key1.len = sizeof(tmp_key1);

    sipdump_string_t key2;
    char tmp_key2[32] = {'\0'};
    key2.str = tmp_key2;
    key2.len = sizeof(tmp_key2);

    socket_network_addr_hash(socket_pair->protocol, &socket_pair->src, &key1);
    socket_network_addr_hash(socket_pair->protocol, &socket_pair->dst, &key2);

    /** 找RTP包 */
    SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "[?] Relation find %s", key1.str);
    sipdump_session_t *session = (sipdump_session_t*)apr_hash_get(mgr->hash_rtp_addr, key1.str, APR_HASH_KEY_STRING);
    if (!session) {
        SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "[?] Relation find %s", key2.str);
        session = (sipdump_session_t*)apr_hash_get(mgr->hash_rtp_addr, key2.str, APR_HASH_KEY_STRING);
    }

    if (session) {
        *pkt_type = SIPDUMP_PKT_TYPE_RTP;
    }
    
    return session;
}

apr_status_t sipdump_session_pkt_save(sipdump_session_t *session, struct pcap_pkthdr *pkt_header, const u_char *pkt_data, network_pkt_type_e pkt_type) {
    assert(session);
    assert(pkt_header);
    assert(pkt_data);

    pcap_dump((u_char*)session->pcap_dumper, pkt_header, pkt_data);
    if (session->pcap_flush) {
        pcap_dump_flush(session->pcap_dumper);
    }
    if (SIPDUMP_PKT_TYPE_UNKNOWN < pkt_type && pkt_type < SIPDUMP_PKT_TYPE_MAX) {
        session->pcap_pkt_cnt[pkt_type]++;
    }

    return APR_SUCCESS;
}


sipdump_session_t *sipdump_session_sip_find(const sipdump_string_t *call_id) {
    assert(call_id);

    sipdump_session_mgr_t *mgr = session_mgr;
    sipdump_session_t *session = (sipdump_session_t*)apr_hash_get(mgr->hash_sip_id, call_id->str, call_id->len);
    return session;
}

apr_status_t sipdump_session_sip_padding(sipdump_session_t *session, const struct network_socket_pair *socket_pair) {
    assert(session);
    assert(socket_pair);

    sipdump_session_mgr_t *mgr = session_mgr;

    relation_clear(mgr->hash_sip_id, session, &session->sip.call_id, "SIP@Call-ID");
    relation_build(mgr->hash_sip_id, session, &session->sip.call_id, "SIP@Call-ID");

    if (!session->sip.socket.src.ip) {
        memcpy(&session->sip.socket, socket_pair, sizeof(struct network_socket_pair));
    }

    return APR_SUCCESS;
}

apr_status_t sipdump_session_sip_sdp_padding(sipdump_session_t *session, const sipdump_sdp_t *sdp) {
    assert(session);
    assert(sdp);

    sipdump_session_mgr_t *mgr = session_mgr;
    int pairing = FALSE;
    sipdump_sdp_t *dst = NULL;

    /** 处理重传包，代理网关的情况 */
    if ((session->sdp[0].has && session->sdp[0].checksum == sdp->checksum) 
        || (session->sdp[1].has && session->sdp[1].checksum == sdp->checksum)) {
        // SIPDUMP_LOG(SIPDUMP_PRIO_WARNING, "%s SDP check sum error", session->uuid);
        return APR_EINPROGRESS;
    }

    /** sdp该填入offser还是answer位（如果是重协商，需要覆盖之前的协商结果） */
    if (!session->sdp[0].has) {
        dst = &session->sdp[0];
        session->sdp[1].has = FALSE;
    } else {
        if (!session->sdp[1].has) {
            pairing = TRUE;
            dst = &session->sdp[1];
        } else {
            SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s SDP renegotiation", session->uuid); 
            memset(&session->sdp[0], 0, sizeof(sipdump_sdp_t));
            memset(&session->sdp[1], 0, sizeof(sipdump_sdp_t));
            dst = &session->sdp[0];
            session->sdp[1].has = FALSE;
        }
    }

    if (!dst) {
        return APR_BADARG;
    }

    /** SDP dump到会话中 */
    memcpy(dst, sdp, sizeof(sipdump_sdp_t));
#ifdef SIPDUMP_MRCP
    if (sdp->mrcp.channel_id.len) {
        dst->mrcp.channel_id.str = apr_pstrndup(session->pool, sdp->mrcp.channel_id.str, sdp->mrcp.channel_id.len);
        dst->mrcp.channel_id.len = sdp->mrcp.channel_id.len;
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s MRCP has actived %s", session->uuid, dst->mrcp.channel_id.str); 
    }

    /** MRCP id */
    if (sdp->mrcp.channel_id.len) {
        relation_clear(mgr->hash_mrcp_id, session, &session->mrcp.channel_id, "MRCP@Chann-Id");
        session->mrcp.channel_id.str = apr_pstrndup(session->pool, sdp->mrcp.channel_id.str, sdp->mrcp.channel_id.len);
        session->mrcp.channel_id.len = sdp->mrcp.channel_id.len;
        relation_build(mgr->hash_mrcp_id, session, &session->mrcp.channel_id, "MRCP@Chann-Id");
    }
#endif
    /** 已经配对 建立RTP&RTCP的网络地址关系 */
    if (pairing) {
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s SDP has negotiated", session->uuid); 
        apr_hash_t *hash = mgr->hash_rtp_addr;
        sipdump_addr_relation_t *addr_relation = &session->addr_relation;
        sipdump_sdp_t *sdp1 = &session->sdp[0];
        sipdump_sdp_t *sdp2 = &session->sdp[1];
        if (sipdump_opt_rtp_filter_test(session->opt, SIPDUMP_RTP_CAPTURE_RTP)) {
            /** rtp audio */
            sipdump_addr_relation_item_t *audio_rtp = &addr_relation->audio_rtp;
            relation_addr_clear(hash, session, audio_rtp, "RTP#a");
            relation_addr_from_sdp(audio_rtp, IPPROTO_UDP, &sdp1->audio_rtp, &sdp2->audio_rtp);
            relation_addr_build(hash, session, audio_rtp, "RTP#a");

            /** rtp video */
            sipdump_addr_relation_item_t *video_rtp = &addr_relation->video_rtp;
            relation_addr_clear(hash, session, video_rtp, "RTP#v");
            relation_addr_from_sdp(video_rtp, IPPROTO_UDP, &sdp1->video_rtp, &sdp2->video_rtp);
            relation_addr_build(hash, session, video_rtp, "RTP#v");
        } else {
            sipdump_addr_relation_item_t *audio_rtp = &addr_relation->audio_rtp;
            relation_addr_from_sdp(audio_rtp, IPPROTO_UDP, &sdp1->audio_rtp, &sdp2->audio_rtp);
            sipdump_addr_relation_item_t *video_rtp = &addr_relation->video_rtp;
            relation_addr_from_sdp(video_rtp, IPPROTO_UDP, &sdp1->video_rtp, &sdp2->video_rtp);
            SIPDUMP_LOG(SIPDUMP_PRIO_DEBUG, "%s RTP is filtered", session->uuid); 
        }

        if (sipdump_opt_rtp_filter_test(session->opt, SIPDUMP_RTP_CAPTURE_RTCP)) {
            SIPDUMP_LOG(SIPDUMP_PRIO_DEBUG, "%s RTCP has paired", session->uuid); 
            /** rtcp audio */
            sipdump_addr_relation_item_t *audio_rtcp = &addr_relation->audio_rtcp;
            relation_addr_clear(hash, session, audio_rtcp, "RTCP#a");
            relation_addr_from_sdp(audio_rtcp, IPPROTO_UDP, &sdp1->audio_rtcp, &sdp2->audio_rtcp);
            relation_addr_build(hash, session, audio_rtcp, "RTCP#a");

            /** rtcp video */
            sipdump_addr_relation_item_t *video_rtcp = &addr_relation->video_rtcp;
            relation_addr_clear(hash, session, video_rtcp, "RTCP#v");
            relation_addr_from_sdp(video_rtcp, IPPROTO_UDP, &sdp1->video_rtcp, &sdp2->video_rtcp);
            relation_addr_build(hash, session, video_rtcp, "RTCP#v");
        } else {
            sipdump_addr_relation_item_t *audio_rtcp = &addr_relation->audio_rtcp;
            relation_addr_from_sdp(audio_rtcp, IPPROTO_UDP, &sdp1->audio_rtcp, &sdp2->audio_rtcp);
            sipdump_addr_relation_item_t *video_rtcp = &addr_relation->video_rtcp;
            relation_addr_from_sdp(video_rtcp, IPPROTO_UDP, &sdp1->video_rtcp, &sdp2->video_rtcp);
            SIPDUMP_LOG(SIPDUMP_PRIO_DEBUG, "%s RTCP is filtered", session->uuid); 
        }
    }

    return APR_SUCCESS;
}

#ifdef SIPDUMP_MRCP
sipdump_session_t *sipdump_session_mrcp_find(const sipdump_string_t *channel_id) {
    assert(channel_id);

    sipdump_session_mgr_t *mgr = session_mgr;
    sipdump_session_t *session = (sipdump_session_t*)apr_hash_get(mgr->hash_mrcp_id, channel_id->str, channel_id->len);
    return session;
}

apr_status_t sipdump_session_mrcp_padding(sipdump_session_t *session, const struct network_socket_pair *socket_pair, const sipdump_mrcp_t *mrcp) {
    assert(session);
    assert(socket_pair);
    assert(mrcp);

    sipdump_addr_relation_item_t *relation = &session->addr_relation.mrcp;
    if (!relation->socket_pair.src.ip) {
        memcpy(&relation->socket_pair, socket_pair, sizeof(struct network_socket_pair));
    }
    return APR_SUCCESS;
}
#endif