#include <assert.h>
#include <string.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_network.h"
#include "sipdump_fragment.h"

#define SIPDUMP_FRAGMENT_MAX 128
#define SIPDUMP_FRAGMENT_HASH_KEY_MAX 32
#define SIPDUMP_FRAGMENT_DATA_MAX (1500  *4)

typedef struct fragment_key_t {
    uint16_t id;
    uint32_t src;
    uint32_t dst;
} fragment_key_t;

typedef struct sipdump_fragment_t {
    
    /** 内存管理 */
    uint32_t index;
    uint32_t used;

    /** key（IP包做key） */
    fragment_key_t key;
    apr_ssize_t hash_key_len; 
    char hash_key[SIPDUMP_FRAGMENT_HASH_KEY_MAX]; /** ip src + dst + id */

    /** 数据 */
    apr_size_t size;
    char data[SIPDUMP_FRAGMENT_DATA_MAX];
} sipdump_fragment_t;

typedef struct sipdump_fragment_mgr_t {
    apr_pool_t *pool;
    apr_hash_t *hash; /** src ip 和 dst ip 和ip id建立关系 */

    sipdump_fragment_t *fragments;
    apr_size_t size;
} sipdump_fragment_mgr_t;
static sipdump_fragment_mgr_t *fragment_mgr = NULL;

static APR_INLINE sipdump_fragment_t *fragment_alloc(network_pkt_t *pkt) {
    assert(pkt);

    sipdump_fragment_mgr_t *mgr = fragment_mgr;

    int i = 0;
    for (i = 0; i < mgr->size; i++) {
        sipdump_fragment_t *f = &mgr->fragments[i];
        if (!f->used) {
            memset(f, 0, sizeof(sipdump_fragment_t));
            f->used = TRUE;
            if (pkt->ipv4) {
                f->key.id = pkt->ipv4->id;
                f->key.src = pkt->ipv4->saddr;
                f->key.dst = pkt->ipv4->daddr;
                f->hash_key_len = snprintf(f->hash_key, sizeof(f->hash_key), "%04X%08X%08X", 
                    f->key.id, f->key.src, f->key.dst);
            }
            f->size = MIN(pkt->size, sizeof(f->data));
            memcpy(f->data, pkt->data, f->size);
            apr_hash_set(mgr->hash, f->hash_key, f->hash_key_len, f);
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "FRAG hash [+] %s -> 0x%08X in 0x%08X", 
                        f->hash_key, f, mgr->hash);
            return f;
        }
    }

    return NULL;
}

static APR_INLINE apr_status_t fragment_free(sipdump_fragment_t *fragment) {
    assert(fragment);
    fragment->used = FALSE;
    sipdump_fragment_mgr_t *mgr = fragment_mgr;
    apr_hash_set(mgr->hash, fragment->hash_key, fragment->hash_key_len, NULL);
    SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "FRAG hash [-] %s hash: 0x%08X", 
        fragment->hash_key, mgr->hash); 
    return APR_SUCCESS;
}

static APR_INLINE sipdump_fragment_t *fragment_find(network_pkt_t *pkt) {
    assert(pkt);

    char hash_key[SIPDUMP_FRAGMENT_HASH_KEY_MAX] = {'\0'};
    apr_ssize_t len = 0;
    if (pkt->ipv4) {
        len = snprintf(hash_key, sizeof(hash_key), "%04X%08X%08X", 
            pkt->ipv4->id, pkt->ipv4->saddr, pkt->ipv4->daddr);
    }

    sipdump_fragment_mgr_t *mgr = fragment_mgr;
    return apr_hash_get(mgr->hash, hash_key, len);
}

static APR_INLINE apr_status_t fragment_reassemble(sipdump_fragment_t *fragment, network_pkt_t *pkt) {
    assert(fragment);
    assert(pkt);

    apr_size_t size = MIN(sizeof(fragment->data) - fragment->size, pkt->size);
    memcpy(fragment->data + fragment->size, pkt->data, size);
    fragment->size += size;

    return APR_SUCCESS;
}

static APR_INLINE apr_status_t fragment_complete(sipdump_fragment_t *fragment, network_pkt_t *pkt) {
    assert(fragment);

    /** 是否是最后一片分片数据 */
    if (pkt->fragment.MF) {
        return APR_ENOTENOUGHENTROPY;
    }

    pkt->data = fragment->data;
    pkt->size = fragment->size;

#ifdef _VERBOSE
    SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "FRAG complete data[%u]: %s", 
        pkt->size, pkt->data);
#endif
    return APR_SUCCESS;
}


apr_status_t sipdump_fragment_init() {
    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, NULL);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "create pool error: %d", status);
        return status;
    }

    sipdump_fragment_mgr_t *mgr = apr_pcalloc(pool, sizeof(sipdump_fragment_mgr_t));
    if (!mgr) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "pcalloc from pool error");
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }
    mgr->pool = pool;
    mgr->hash = apr_hash_make(pool);

    if (!mgr->hash) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "make hash from pool error");
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }

    mgr->size = SIPDUMP_FRAGMENT_MAX;
    mgr->fragments = (sipdump_fragment_t*)apr_pcalloc(pool, sizeof(sipdump_fragment_t)  *mgr->size);
    if (!mgr->fragments) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "pcalloc from pool error");
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }
    int i = 0;
    for (i = 0; i < mgr->size; i++) {
        sipdump_fragment_t *f = &mgr->fragments[i];
        f->index = i;
    }

    fragment_mgr = mgr;
    return APR_SUCCESS;
}

apr_status_t sipdump_fragment_uninit() {

    sipdump_fragment_mgr_t *mgr = fragment_mgr;
    if (!mgr) {
        return APR_SUCCESS;
    }

    if (mgr->pool) { 
        apr_pool_destroy(mgr->pool);
    }

    fragment_mgr = NULL;
    return APR_SUCCESS;
}

apr_status_t sipdump_fragment_cache(network_pkt_t *pkt) {
    assert(pkt);

    sipdump_fragment_t *f = NULL;
    if (pkt->fragment.MF && !pkt->offset) {
        /** 第一个分片 */
        f = fragment_alloc(pkt);
        if (!f) {
            SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "FRAG not enough memory");
            return APR_EINTR;
        }
        if (pkt->ipv4) {
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "FRAG head. [%04x:%08x:%08x] #%u on %u", 
                pkt->ipv4->id, pkt->ipv4->saddr, pkt->ipv4->daddr, 
                pkt->size, f->index); 
        }
        
        return APR_ENOTENOUGHENTROPY;
    } else if (pkt->offset) {
        /** 后续分片到达，寻找之前缓存的数据 */
        f = fragment_find(pkt);
        if (!f) {
            return APR_NOTFOUND;
        }

        /** 组合起来 */
        fragment_reassemble(f, pkt);

        /** 是否完整 */
        apr_status_t status = fragment_complete(f, pkt);
        if (pkt->ipv4) {
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "FRAG next. [%04x:%08x:%08x] #%u on %u %s", 
                pkt->ipv4->id, pkt->ipv4->saddr, pkt->ipv4->daddr, 
                f->size, f->index, status == APR_ENOTENOUGHENTROPY ? "Need More" : "Completed"); 
        }
        if (status == APR_SUCCESS) {
            fragment_free(f);
        }

        return status;
    }

    return APR_SUCCESS;
}


