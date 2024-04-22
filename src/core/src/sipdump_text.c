#include <assert.h>
#include <string.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_hash.h>

#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_text.h"

apr_status_t sipdump_text_parse(const char *data, apr_size_t size, char sp, sipdump_text_field_t *fields, apr_size_t field_size) {
    assert(data);
    assert(fields);

    const char *tmp = data;
    apr_size_t field_match = 0;
    int line_index = 0;
    
    do {
        apr_size_t i = 0;
        for (i = 0; i < field_size; i++) {
            sipdump_text_field_t *field = &fields[i];
            // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "TEXT #%u cmp field: %s(%d) %s(%d) %.*s(%d)", line_index, field->hdr.str, field->hdr.len, field->shdr.str, field->shdr.len, field->hdr.len, tmp, field->hdr.len); 
            if (!field->match) {
                const char *hdr_str = NULL;
                apr_size_t hdr_len = 0;
                if (!SIPDUMP_ZSTR(field->hdr.str) && !strncasecmp(tmp, field->hdr.str, field->hdr.len)) {
                    hdr_str = field->hdr.str;
                    hdr_len = field->hdr.len;
                } else if (!SIPDUMP_ZSTR(field->shdr.str) && !strncmp(tmp, field->shdr.str, field->shdr.len)) {
                    hdr_str = field->shdr.str;
                    hdr_len = field->shdr.len;
                } else  {
                    continue;
                }
                // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "TEXT #%u cmp success: %u: %.*s =? %s(%d)", line_index, i, hdr_len, tmp, hdr_str, hdr_len); 
                /** 跳过头域名字 */
                tmp += hdr_len;
                TEXT_SPACES_SKIP(tmp);
                /** 跳过分隔符 */
                if (*tmp == sp) {
                    tmp += 1;
                } else {
                    /** 这个头域匹配出现了异常，跳过 */
                    SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "TEXT line %u field -> %u:%s(%d) error", 
                        line_index, i, hdr_str, hdr_len); 
                    continue;
                }
                TEXT_SPACES_SKIP(tmp);
                field->val.str = (char*)tmp;
                /** 找到末端的结束位置 */
                SIPDUMP_TEXT_LINE_LEN_GET(tmp, data, size, field->val.len);
                field->match = TRUE;
                field_match++;
                SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "TEXT line: %u header: %s(%d) value: %.*s(%d) to index: %u", 
                    line_index, 
                    hdr_str, hdr_len, 
                    field->val.len, field->val.str, field->val.len, i
                ); 
                break;
            }
        }

        /** 已经全部找到 */
        if (field_match == field_size) {
            break;
        }

        /** 空行 */
        if (*tmp == TEXT_TOKEN_CR) {
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "TEXT line empty to index: %u", line_index); 
            break;
        }

        /** 开始下一行 */
        tmp = strchr(tmp, TEXT_TOKEN_LF);
        if (!tmp || tmp - data > size) {
            break;
        }
        tmp += 1;
        line_index++;
    } while(tmp && tmp - data < size);

    return APR_SUCCESS;
}

apr_status_t sipdump_text_complete_parse(const char *data, apr_size_t size, apr_pool_t *pool, apr_hash_t *hdr, char **body, apr_size_t *body_size) {
    assert(data);
    assert(pool);

    const char *tmp = data;
    int line_index = 0;
    
    /** 跳过起始行 */
    tmp = strchr(tmp, TEXT_TOKEN_LF);
    if (tmp) {
        tmp++;
    }

    do {
        apr_size_t i = 0;
        /** 空行 */
        if (*tmp == TEXT_TOKEN_CR || *tmp == TEXT_TOKEN_LF) {
            while((*tmp == TEXT_TOKEN_CR || *tmp == TEXT_TOKEN_LF)) {
                tmp++;
            }

            if (tmp - data < size) {
                if (body_size) {
                    *body_size = size - (tmp - data);
                }
                if (body) {
                    *body = apr_pstrndup(pool, tmp, size - (tmp - data));
                }
                SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "TEXT line: %u body: %.*s(%d)",
                    line_index, size - (tmp - data), tmp, size - (tmp - data));
                break;
            }
        } else {
            const char *h_start = tmp;
            TEXT_SPACES_SKIP(h_start);
            const char *h_end = NULL;
            const char *sp = strchr(h_start, TEXT_TOKEN_COLON);
            h_end = sp;
            if (h_end) {
                h_end--;
                while(*h_end == TEXT_TOKEN_SP) {
                    h_end--;
                }

                const char *v_start = sp + 1;
                TEXT_SPACES_SKIP(v_start);
                const char *v_end = v_start;
                while(*v_end != TEXT_TOKEN_CR && *v_end != TEXT_TOKEN_LF) {
                    v_end++;
                }

                apr_ssize_t h_len = h_end - h_start + 1;
                char* h = apr_pstrndup(pool, h_start, h_len);
                sipdump_string_t *v = apr_pcalloc(pool, sizeof(sipdump_string_t));
                v->str = apr_pstrndup(pool, v_start, v_end - v_start);
                v->len = v_end - v_start;
                SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "TEXT line: %u header: %s(%d) value: %.*s(%d)",
                    line_index, h, h_len, v->len, v->str, v->len);
                apr_hash_set(hdr, h, h_len, v);
            }
        }

        /** 开始下一行 */
        tmp = strchr(tmp, TEXT_TOKEN_LF);
        if (!tmp || tmp - data > size) {
            break;
        }
        tmp += 1;
        line_index++;
    } while(tmp && tmp - data < size);

    return APR_SUCCESS;
}