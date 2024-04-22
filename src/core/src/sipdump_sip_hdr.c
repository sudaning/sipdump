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
#include "sipdump_sip.h"
#include "sipdump_sip_hdr.h"

static apr_status_t sipdump_sip_hdr_cseq_parse(const char *data, apr_size_t size, sipdump_sip_hdr_cseq_t *hdr_cseq) {
    assert(data);
    assert(hdr_cseq);

    const char *tmp = data;

    TEXT_SPACES_SKIP(tmp);
    hdr_cseq->seq = (unsigned int)apr_atoi64(tmp);
    const char *method_start = strchr(tmp, TEXT_TOKEN_SP);
    if (!method_start) {
        return APR_BADARG;
    }

    TEXT_SPACES_SKIP(method_start);
    return sipdump_sip_method_get(method_start, -1, &hdr_cseq->method, &hdr_cseq->method_name);
}

static apr_status_t sipdump_sip_hdr_addr_parse(char *data, apr_size_t size, struct sipdump_sip_hdr_addr_t *hdr_addr) {
    sipdump_string_t displayname = {NULL, 0};
    sipdump_string_t scheme = {NULL, 0};
    sipdump_string_t url = {NULL, 0};
    sipdump_string_t user = {NULL, 0};
    sipdump_string_t host = {NULL, 0};
    sipdump_string_t port = {NULL, 0};
    sipdump_string_t params = {NULL, 0};

    char *d = NULL; 
    apr_size_t len = 0;
    for(d = data, len = 0; *d && len < size;) {
        switch(*d) {
            case '"': {
                if (!displayname.str) {
                    displayname.str = d + 1;
                } else if (!displayname.len) {
                    displayname.len = d - displayname.str;
                }
                break;
            }
            case '<': {
                if (!url.str) {
                    url.str = d + 1;
                }
                if (!displayname.str) {
                    displayname.str = d;
                    displayname.len = d - displayname.str;
                }
                break;
            }
            case '>': {
                if (url.str) {
                    url.len = d - url.str;
                }
                break;
            }
        }
        len++;
        d++;
    }

    if (!url.str) {
        url.str = data;
        url.len = size; 
    }

    // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "displayname %.*s %u", displayname.len, displayname.str, displayname.len);
    // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "url %.*s %u", url.len, url.str, url.len);

    if (!strncmp(url.str, "sip:", sizeof("sip:") - 1)) {
        user.str = url.str + sizeof("sip:") - 1;
        scheme.str = "sip";
        scheme.len = sizeof("sip") - 1;
    } else if (!strncmp(url.str, "sips:", sizeof("sips:") - 1)) {
        user.str = url.str + sizeof("sips:") - 1;
        scheme.str = "sips";
        scheme.len = sizeof("sips") - 1;
    } else if (!strncmp(url.str, "tel:", sizeof("tel:") - 1)) {
        user.str = url.str + sizeof("tel:") - 1;
        user.len = url.len - (sizeof("tel:") - 1);
        scheme.str = "tel";
        scheme.len = sizeof("tel") - 1;
    } else {
        return APR_EINVAL;
    }

    host.str = strchr(user.str, '@');
    if (host.str && host.str - user.str < url.len) {
        user.len = host.str - user.str;
        host.str = host.str + 1;
        host.len = url.len - (host.str - url.str);
    } else {
        if (strncmp(scheme.str, "tel", scheme.len)) {
            host.str = user.str;
            host.len = url.len - (user.str - url.str);
        }
    }

    if (host.str && host.str - user.str < url.len) {
        port.str = strchr(host.str, ':');
        if (port.str && port.str - host.str < url.len) {
            port.str = port.str + 1;
            port.len = host.len - (port.str - host.str);
        }
    }

    params.str = strchr(url.str, ';');
    if (params.str && params.str - url.str < url.len) {
        params.str++;
        params.len = size - (params.str - data);
    }

    memcpy(&hdr_addr->display, &displayname, sizeof(sipdump_string_t));
    memcpy(&hdr_addr->scheme, &scheme, sizeof(sipdump_string_t));
    memcpy(&hdr_addr->user, &user, sizeof(sipdump_string_t));
    memcpy(&hdr_addr->host, &host, sizeof(sipdump_string_t));
    memcpy(&hdr_addr->port, &port, sizeof(sipdump_string_t));
    memcpy(&hdr_addr->params, &params, sizeof(sipdump_string_t));

    return APR_SUCCESS;
}

apr_status_t sipdump_sip_hdr_parse(const char *data, apr_size_t size, sipdump_text_field_t* hdr_fields, apr_uint32_t hdr_field_count, sipdump_sip_hdr_t *hdr) {
    assert(data);
    assert(hdr);

    apr_status_t status = sipdump_text_parse(data, size, TEXT_TOKEN_COLON, hdr_fields, hdr_field_count);
    if (status != APR_SUCCESS) {
        return status;
    }

    int i = 0;
    for (i = 0; i < hdr_field_count; i++) {
        sipdump_text_field_t *f = &hdr_fields[i];
        if (!f->match) {
            continue;
        }
        
        if (!strcmp(f->hdr.str, SIP_HDR_CALL_ID)) {
            /** Call-ID */
            hdr->call_id.str = f->val.str;
            hdr->call_id.len = f->val.len;
        } else if (!strcmp(f->hdr.str, SIP_HDR_FROM)) {
            /** From */
            if (f->val.str && f->val.len) {
                status = sipdump_sip_hdr_addr_parse(f->val.str, f->val.len, &hdr->from);
                if (status != APR_SUCCESS) {
                    return status;
                }
            }
        } else if (!strcmp(f->hdr.str, SIP_HDR_TO)) {
            /** To */
            if (f->val.str && f->val.len) {
                status = sipdump_sip_hdr_addr_parse(f->val.str, f->val.len, &hdr->to);
                if (status != APR_SUCCESS) {
                    return status;
                }
            }
        } else if (!strcmp(f->hdr.str, SIP_HDR_CSEQ)) {
            /** CSeq */
            if (f->val.str && f->val.len) {
                status = sipdump_sip_hdr_cseq_parse(f->val.str, f->val.len, &hdr->cseq);
                if (status != APR_SUCCESS) {
                    return status;
                }
            }
        } else if (!strcmp(f->hdr.str, SIP_HDR_CONTENT_LEN)) {
            /** Content-Length */
            if (f->val.str && f->val.len) {
                hdr->content_length = (unsigned int)apr_atoi64(f->val.str);
            }
        } else if (!strcmp(f->hdr.str, SIP_HDR_CONTENT_TYPE)) {
            /** Content-Type */
            hdr->content_type.str = f->val.str;
            hdr->content_type.len = f->val.len;
        }

        if (hdr->count < sipdump_arraylen(hdr->hdrs)) {
            sipdump_sip_hdr_common_t *ext = &hdr->hdrs[hdr->count++];
            ext->name.str = f->hdr.str;
            ext->name.len = f->hdr.len;
            ext->value.str = f->val.str;
            ext->value.len = f->val.len;
        }
    }

    return APR_SUCCESS;
}