#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_text.h"
#include "sipdump_opt.h"
#include "sipdump_sip_hdr.h"
#include "sipdump_sip.h"

struct sip_methods_t {
    sipdump_sip_method_e method;
    const char *name;
    apr_size_t name_size;
};
typedef struct sip_methods_t sip_methods_t;

static const sip_methods_t sip_methods[] = {
    {SIPDUMP_SIP_METHOD_INVITE, "INVITE", sizeof("INVITE") - 1},
    {SIPDUMP_SIP_METHOD_UPDATE, "UPDATE", sizeof("UPDATE") - 1},
    {SIPDUMP_SIP_METHOD_BYE, "BYE", sizeof("BYE") - 1},
    {SIPDUMP_SIP_METHOD_ACK, "ACK", sizeof("ACK") - 1},
    {SIPDUMP_SIP_METHOD_CANCEL, "CANCEL", sizeof("CANCEL") - 1},
    {SIPDUMP_SIP_METHOD_OPTIONS, "OPTIONS", sizeof("OPTIONS") - 1},
    {SIPDUMP_SIP_METHOD_REGISTER, "REGISTER", sizeof("REGISTER") - 1},
    {SIPDUMP_SIP_METHOD_INFO, "INFO", sizeof("INFO") - 1},
    {SIPDUMP_SIP_METHOD_PRACK, "PRACK", sizeof("PRACK") - 1},
    {SIPDUMP_SIP_METHOD_MESSAGE, "MESSAGE", sizeof("MESSAGE") - 1},
    {SIPDUMP_SIP_METHOD_SUBSCRIBE, "SUBSCRIBE", sizeof("SUBSCRIBE") - 1},
    {SIPDUMP_SIP_METHOD_NOTIFY, "NOTIFY", sizeof("NOTIFY") - 1},
    {SIPDUMP_SIP_METHOD_REFER, "REFER", sizeof("REFER") - 1},
    {SIPDUMP_SIP_METHOD_PUBLISH, "PUBLISH", sizeof("PUBLISH") - 1}
};

#define SIP_2_0 "SIP/2.0"


sipdump_text_field_t base_fields[] = {
    SIPDUMP_TEXT_HDR_ITEM_INIT(SIP_HDR_CALL_ID, SIP_HDR_CALL_ID_S),
    SIPDUMP_TEXT_HDR_ITEM_INIT(SIP_HDR_CSEQ, SIP_HDR_BASE_S),
    SIPDUMP_TEXT_HDR_ITEM_INIT(SIP_HDR_CONTENT_LEN, SIP_HDR_CONTENT_LEN_S),
    SIPDUMP_TEXT_HDR_ITEM_INIT(SIP_HDR_CONTENT_TYPE, SIP_HDR_CONTENT_TYPE_S),
    SIPDUMP_TEXT_HDR_ITEM_INIT(SIP_HDR_FROM, SIP_HDR_FROM_S),
    SIPDUMP_TEXT_HDR_ITEM_INIT(SIP_HDR_TO, SIP_HDR_TO_S),
};

struct {
    apr_pool_t *pool;
    sipdump_text_field_t *fields;
    int field_count;
} hdr_mgr;

apr_status_t sipdump_sip_hdr_pre_parse_add(char hdrs[][SIPDUMP_HEADER_NAME_MAX], apr_size_t count) {
    const char *ext_hdrs[64] = {NULL};
    int ext_count = 0;
    int i = 0;
    for (i = 0; i < count; i++) {
        const char *h = hdrs[i];
        // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "SIP hdr pre parse add: %s", h);
        int j = 0;
        int found = FALSE;
        for (j = 0; j < sipdump_arraylen(hdr_mgr.fields); j++) {
            sipdump_text_field_t *bh = &hdr_mgr.fields[j];
            if (!strncasecmp(h, bh->hdr.str, bh->hdr.len)) {
                found = TRUE;
                break;
            }
        }

        if (!found) {
            if (ext_count < sipdump_arraylen(ext_hdrs)) {
                ext_hdrs[ext_count++] = h;
                SIPDUMP_LOG(SIPDUMP_PRIO_DEBUG, "SIP ext header: %s", h);
            } else {
                break;
            }
        }
    }

    int field_count = hdr_mgr.field_count + ext_count;
    if (field_count > SIPDUMP_HDR_EXT_MAX) {
        return APR_EINTR;
    }

    sipdump_text_field_t *fields = apr_pcalloc(hdr_mgr.pool, sizeof(sipdump_text_field_t) * field_count);
    memcpy(fields, hdr_mgr.fields, sizeof(sipdump_text_field_t) * hdr_mgr.field_count);
    hdr_mgr.fields = fields;
    if (ext_count) {
        fields += hdr_mgr.field_count;
        int m = 0;
        for (m = 0; m < ext_count; m++) {
            sipdump_text_field_t *f = &fields[m];
            f->hdr.str = apr_pstrdup(hdr_mgr.pool, ext_hdrs[m]);
            f->hdr.len = strlen(f->hdr.str);
        }
    }
    hdr_mgr.field_count = field_count;

#if 0
    if (sipdump_log_priority_trace()) {
        SIPDUMP_LOG(SIPDUMP_PRIO_DEBUG, "SIP header total: %u", hdr_mgr.field_count);
        int i = 0;
        for (i = 0; i < hdr_mgr.field_count; i++) {
            sipdump_text_field_t *f = &hdr_mgr.fields[i];
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "SIP header hdr: %s", f->hdr.str);
        }
    }
#endif
    return APR_SUCCESS;
}

static apr_status_t sipdump_sip_hdr_pre_parse_init(char hdrs[][SIPDUMP_HEADER_NAME_MAX], apr_size_t count) {
    assert(hdrs);

    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, NULL);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "create pool error: %d", status);
        return status;
    }

    sipdump_text_field_t *fields = apr_pcalloc(pool, sizeof(sipdump_text_field_t) * sipdump_arraylen(base_fields));
    memcpy(fields, base_fields, sizeof(sipdump_text_field_t) * sipdump_arraylen(base_fields));
    hdr_mgr.fields = fields;
    hdr_mgr.field_count = sipdump_arraylen(base_fields);
    hdr_mgr.pool = pool;

    return sipdump_sip_hdr_pre_parse_add(hdrs, count);
}

apr_status_t sipdump_sip_init_opt(sipdump_opt_t* opt) {
    assert(opt);

    apr_size_t hdr_count = 0;
    char hdrs[8][SIPDUMP_HEADER_NAME_MAX];
    memset(hdrs, 0, sizeof(hdrs));

    const char *record_path = sipdump_opt_pcap_record_path_get(opt);
    const char *tmp = record_path;
    while(tmp) {
        tmp = strstr(tmp, "${sip_h_");
        if (!tmp) {
            break;
        }
        tmp += sizeof("${sip_h_") - 1;
        const char *end = strchr(tmp, '}');
        if (!end) {
            break;
        }

        char *hdr = hdrs[hdr_count];
        strncpy(hdr, tmp, MIN(end - tmp, sizeof(hdrs[0])));

        hdr_count++;
    }

    if (!strstr(record_path, "sip_call_id") && !hdr_count) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "SIP check the record path uniqueness error. "
            "You must specify 'sip_call_id' or 'sip_h_xxx' to ensure uniqueness");
        return APR_EINVAL;
    }

    // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "SIP ext hdr: %u", hdr_count);
    
    sipdump_sip_hdr_pre_parse_init(hdrs, hdr_count);
    return APR_SUCCESS;
}

apr_status_t sipdump_sip_uninit() {
    if (hdr_mgr.pool) {
        apr_pool_destroy(hdr_mgr.pool);
    }
    return APR_SUCCESS;
}

apr_status_t sipdump_sip_start_line_get(const char *data, apr_size_t size, sipdump_sip_method_e *method, const char **method_name, sipdump_sip_code *code) {
    assert(data);

    if (!strncasecmp(data, SIP_2_0, sizeof(SIP_2_0) - 1)) {
        const char *tmp = data + (sizeof(SIP_2_0) - 1);
        if (code) {
            *code = (sipdump_sip_code)apr_atoi64(tmp + 1);
        }
        return APR_SUCCESS;
    }

    return sipdump_sip_method_get(data, size, (int*)method, method_name);
}

apr_status_t sipdump_sip_method_get(const char *data, apr_size_t size, int *method, const char **method_name) {
    assert(data);

    if (method) {
        *method = SIPDUMP_SIP_METHOD_UNKNOWN;
    }
    if (method_name) {
        *method_name = "UNKNOWN";
    }

    int i = 0;
    for (i = 0; i < sipdump_arraylen(sip_methods); i++) {
        const sip_methods_t *sip_method = &sip_methods[i];
        if (!strncasecmp(data, sip_method->name, sip_method->name_size)) {
            if (method) {
                *method = sip_method->method;
            }
            if (method_name) {
                *method_name = sip_method->name;
            }
            return APR_SUCCESS;
        }
    }

    return APR_NOTFOUND;
}

apr_status_t sipdump_sip_parse(const char *data, apr_size_t size, sipdump_sip_method_e method, sipdump_sip_code code, sipdump_sip_t *sip) {
    assert(data);
    assert(sip);

    sip->method = method;
    sip->code = code;

    /** 指定解析其中几个头域 */
    sipdump_text_field_t fields[SIPDUMP_HDR_EXT_MAX];
    memcpy(fields, hdr_mgr.fields, sizeof(sipdump_text_field_t) * hdr_mgr.field_count);
#if 0
    if (sipdump_log_priority_trace()) {
        SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "SIP parse hdr total: %u", hdr_mgr.field_count);
        int i = 0;
        for (i = 0; i < hdr_mgr.field_count; i++) {
            sipdump_text_field_t *f = &fields[i];
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "SIP parse hdr: %s", f->hdr.str);
        }
    }
#endif
    apr_status_t status = sipdump_sip_hdr_parse(data, size, fields, hdr_mgr.field_count, &sip->hdr);
    if (sip->hdr.content_length && sip->hdr.content_type.str 
        && !strncasecmp(sip->hdr.content_type.str, SIP_VALUE_APPLICATION_SDP, sizeof(SIP_VALUE_APPLICATION_SDP) - 1)) {
        sip->sdp.has = TRUE;
    }

    return status;
}

const sipdump_string_t *sipdump_sip_call_id_get(const sipdump_sip_t *sip) {
    assert(sip);
    return &sip->hdr.call_id;
}

const sipdump_sip_hdr_from_t *sipdump_sip_from_get(const sipdump_sip_t *sip) {
    assert(sip);
    return &sip->hdr.from;
}

const sipdump_sip_hdr_to_t *sipdump_sip_to_get(const sipdump_sip_t *sip) {
    assert(sip);
    return &sip->hdr.to;
}

int sipdump_sip_create_session_method_test(sipdump_sip_method_e method) {
    switch (method) {
        case SIPDUMP_SIP_METHOD_INVITE:
        // case SIPDUMP_SIP_METHOD_REGISTER:
            return TRUE;
        
        default:
            break;
    }
    return FALSE;
}