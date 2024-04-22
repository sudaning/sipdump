#include <assert.h>
#include <string.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_text.h"
#include "sipdump_mrcp.h"

struct sipdump_mrcp_hdr_t {
    apr_hash_t *hdrs;
};

struct sipdump_mrcp_request_t {
    sipdump_mrcp_request_e method;
    const char *method_name;
};

struct sipdump_mrcp_response_t {
    sipdump_mrcp_code code;
    sipdump_mrcp_request_state_e request_state;
    const char *request_state_name;
};

struct sipdump_mrcp_event_t {
    sipdump_mrcp_event_e event;
    const char *event_name;
    sipdump_mrcp_request_state_e request_state;
    const char *request_state_name;
};

struct sipdump_mrcp_request_line_t {
    apr_int64_t request_id;
    sipdump_mrcp_message_type_e type;
    union {
        struct sipdump_mrcp_request_t request;
        struct sipdump_mrcp_response_t response;
        struct sipdump_mrcp_event_t event;
    } message;
};

struct sipdump_mrcp_t {
    apr_pool_t *pool;
    struct sipdump_mrcp_request_line_t request_line;
    struct sipdump_mrcp_hdr_t hdr;
};

struct mrcp_request_t {
    int request;
    const char *name;
    apr_size_t name_size;
};
typedef struct mrcp_request_t mrcp_request_t;
static const mrcp_request_t mrcp_requests[] = {
    {SIPDUMP_MRCP_REQUEST_RECOGNIZE, "RECOGNIZE", sizeof("RECOGNIZE") - 1},
    {SIPDUMP_MRCP_REQUEST_STOP, "STOP", sizeof("STOP") - 1},
    {SIPDUMP_MRCP_REQUEST_SET_PARAMS, "SET-PARAMS", sizeof("SET-PARAMS") - 1},
    {SIPDUMP_MRCP_REQUEST_GET_PARAMS, "GET-PARAMS", sizeof("GET-PARAMS") - 1},
    {SIPDUMP_MRCP_REQUEST_DEFINE_GRAMMAR, "DEFINE-GRAMMAR", sizeof("DEFINE-GRAMMAR") - 1},
    {SIPDUMP_MRCP_REQUEST_INTERPRET, "INTERPRET", sizeof("INTERPRET") - 1},
    {SIPDUMP_MRCP_REQUEST_GET_RESULT, "GET_RESULT", sizeof("GET_RESULT") - 1},
    {SIPDUMP_MRCP_REQUEST_START_INPUT_TIMERS, "START_INPUT_TIMERS", sizeof("START_INPUT_TIMERS") - 1},
    {SIPDUMP_MRCP_REQUEST_START_PHRASE_ENROLLMENT, "START_PHRASE_ENROLLMENT", sizeof("START_PHRASE_ENROLLMENT") - 1},
    {SIPDUMP_MRCP_REQUEST_ENROLLMENT_ROLLBACK, "ENROLLMENT_ROLLBACK", sizeof("ENROLLMENT_ROLLBACK") - 1},
    {SIPDUMP_MRCP_REQUEST_END_PHRASE_ENROLLMENT, "END_PHRASE_ENROLLMENT", sizeof("END_PHRASE_ENROLLMENT") - 1},
    {SIPDUMP_MRCP_REQUEST_MODIFY_PHRASE, "MODIFY_PHRASE", sizeof("MODIFY_PHRASE") - 1},
    {SIPDUMP_MRCP_REQUEST_DELETE_PHRASE, "DELETE_PHRASE", sizeof("DELETE_PHRASE") - 1},
};

struct mrcp_event_t {
    sipdump_mrcp_event_e event;
    const char *name;
    apr_size_t name_size;
};
typedef struct mrcp_event_t mrcp_event_t;
static const mrcp_event_t mrcp_events[] = {
    {SIPDUMP_MRCP_EVENT_START_OF_INPUT, "START-OF-INPUT", sizeof("START-OF-INPUT") - 1},
    {SIPDUMP_MRCP_EVENT_RECOGNITION_COMPLETE, "RECOGNITION-COMPLETE", sizeof("RECOGNITION-COMPLETE") - 1},
    {SIPDUMP_MRCP_EVENT_INTERPRETATION_COMPLETE, "INTERPRETATION-COMPLETE", sizeof("INTERPRETATION-COMPLETE") - 1},
};

struct mrcp_request_state_t {
    sipdump_mrcp_request_state_e state;
    const char *name;
    apr_size_t name_size;
};
typedef struct mrcp_request_state_t mrcp_request_state_t;
static const mrcp_request_state_t mrcp_request_states[] = {
    {SIPDUMP_MRCP_REQUEST_STATE_COMPLETE, "COMPLETE", sizeof("COMPLETE") - 1},
    {SIPDUMP_MRCP_REQUEST_STATE_IN_PROGRESS, "IN-PROGRESS", sizeof("IN-PROGRESS") - 1},
    {SIPDUMP_MRCP_REQUEST_STATE_PENDING, "PENDING", sizeof("PENDING") - 1},
};

#define MRCP_2_0 "MRCP/2.0"

static apr_status_t sipdump_mrcp_request_find(const char *data, sipdump_mrcp_request_e *request, const char **request_name) {
    assert(data);

    int i = 0;
    for (i = 0; i < sipdump_arraylen(mrcp_requests); i++) {
        const mrcp_request_t *mrcp_request = &mrcp_requests[i];
        // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "C: %.*s ?= %s", mrcp_request->name_size, data, mrcp_request->name); 
        if (!strncasecmp(data, mrcp_request->name, mrcp_request->name_size)) {
            if (request) {
                *request = mrcp_request->request;
            }
            if (request_name) {
                *request_name = mrcp_request->name;
            }
            return APR_SUCCESS;
        }
    }

    return APR_NOTFOUND;
}


static apr_status_t sipdump_mrcp_request_state_find(const char *data, sipdump_mrcp_request_state_e *state, const char **state_name) {
    assert(data);

    int i = 0;
    for (i = 0; i < sipdump_arraylen(mrcp_request_states); i++) {
        const mrcp_request_state_t *mrcp_request_state = &mrcp_request_states[i];
        // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "C: %.*s ?= %s", mrcp_request_state->name_size, data, mrcp_request_state->name); 
        if (!strncasecmp(data, mrcp_request_state->name, mrcp_request_state->name_size)) {
            if (state) {
                *state = mrcp_request_state->state;
            }
            if (state_name) {
                *state_name = mrcp_request_state->name;
            }
            return APR_SUCCESS;
        }
    }

    return APR_NOTFOUND;
}

static apr_status_t sipdump_mrcp_event_find(const char *data, sipdump_mrcp_event_e *event, const char **event_name) {
    assert(data);

    int i = 0;
    for (i = 0; i < sipdump_arraylen(mrcp_events); i++) {
        const mrcp_event_t *mrcp_event = &mrcp_events[i];
        // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "C: %.*s ?= %s", mrcp_event->name_size, data, mrcp_event->name); 
        if (!strncasecmp(data, mrcp_event->name, mrcp_event->name_size)) {
            if (event) {
                *event = mrcp_event->event;
            }
            if (event_name) {
                *event_name = mrcp_event->name;
            }
            return APR_SUCCESS;
        }
    }

    return APR_NOTFOUND;
}

static apr_status_t sipdump_mrcp_request_line_parse(const char *data, apr_size_t size, struct sipdump_mrcp_request_line_t *request_line) {
    assert(data);
    assert(request_line);

    if (!strncasecmp(data, MRCP_2_0, sizeof(MRCP_2_0) - 1)) {
        /** 找到起始行的结束位置 */
        const char *endline = strchr(data, '\n');
        if (!endline || (endline - data) > size) {
            return APR_BADARG;
        }
        /** 倒数第二个是 \r 则去掉，并且指向起始行最后一个有效字符 */
        if (*(endline - 1) == '\r') {
            endline -= 2;
        } else {
            endline -= 1;
        }

        /** 跳过协议头的版本说明 */
        const char *tmp = data + (sizeof(MRCP_2_0));

        /** 得到包长度 */
        apr_int64_t length = apr_atoi64(tmp);

        /** 下一个空格，要么是数字，要么是字符串 */
        tmp = strchr(tmp, ' ');
        if (!tmp || endline < tmp) {
            return APR_BADARG;
        }
        TEXT_SPACES_SKIP(tmp);
        
        apr_int64_t reqid = apr_atoi64(tmp);
        if (reqid) {
            request_line->type = SIPDUMP_MRCP_MSG_TYPE_RESPONSE;
            /** 是数字，则是响应消息 */
            tmp = strchr(tmp, ' ');
            if (!tmp || endline < tmp) {
                return APR_BADARG;
            }
            TEXT_SPACES_SKIP(tmp);

            apr_int64_t status_code = apr_atoi64(tmp);
            if (status_code) {
                request_line->message.response.code = status_code;
            } else {
                return APR_BADARG;
            }

            tmp = strchr(tmp, ' ');
            if (!tmp || endline < tmp) {
                return APR_BADARG;
            }
            TEXT_SPACES_SKIP(tmp);
            

            apr_status_t status = sipdump_mrcp_request_state_find(tmp, &request_line->message.response.request_state, &request_line->message.response.request_state_name);
            if (status != APR_SUCCESS) {
                return status;
            }

        } else {
            /** 不是数字，则是请求消息或者事件 */
            apr_status_t status = sipdump_mrcp_request_find(tmp, &request_line->message.request.method, &request_line->message.request.method_name);
            if (status != APR_SUCCESS) {
                status = sipdump_mrcp_event_find(tmp, &request_line->message.event.event, &request_line->message.event.event_name);
                if (status != APR_SUCCESS) {
                    return status;
                } else {
                    request_line->type = SIPDUMP_MRCP_MSG_TYPE_EVENT;
                }
            } else {
                request_line->type = SIPDUMP_MRCP_MSG_TYPE_REQUEST;
            }

            /** 请求ID */
            tmp = strchr(tmp, ' ');
            if (!tmp || endline < tmp) {
                return APR_BADARG;
            }
            TEXT_SPACES_SKIP(tmp);

            reqid = apr_atoi64(tmp);

            /** 事件消息的请求状态 */
            if (request_line->type == SIPDUMP_MRCP_MSG_TYPE_EVENT) {
                tmp = strchr(tmp, ' ');
                if (tmp && endline > tmp) {
                    TEXT_SPACES_SKIP(tmp);
                    apr_status_t status = sipdump_mrcp_request_state_find(tmp, &request_line->message.event.request_state, &request_line->message.event.request_state_name);
                    if (status != APR_SUCCESS) {
                        return status;
                    }
                }
            }
        }

        request_line->request_id = reqid;

        return APR_SUCCESS;
    }

    return APR_NOTFOUND;
}

apr_status_t sipdump_mrcp_parse(const char *data, apr_size_t size, sipdump_mrcp_t **mrcp) {
    assert(data);
    assert(mrcp);

    struct sipdump_mrcp_request_line_t request_line;
    apr_status_t status = sipdump_mrcp_request_line_parse(data, size, &request_line);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "MRCP parse request line error. code: %u", status); 
        return status;
    }

    apr_pool_t *pool = NULL;
    status = apr_pool_create(&pool, NULL);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "MRCP create pool error: %d", status);
        return status;
    }
    sipdump_mrcp_t *m = apr_pcalloc(pool, sizeof(sipdump_mrcp_t));
    m->pool = pool;
    m->hdr.hdrs = apr_hash_make(pool);
    memcpy(&m->request_line, &request_line, sizeof(struct sipdump_mrcp_request_line_t));

    status = sipdump_text_complete_parse(data, size, pool, m->hdr.hdrs, NULL, NULL);
    if (status != APR_SUCCESS) {
        apr_pool_destroy(pool);
        return status;
    }

    SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "MRCP parse hdr count: %d", apr_hash_count(m->hdr.hdrs));

    *mrcp = m;

    return status;
}

apr_status_t sipdump_mrcp_free(const sipdump_mrcp_t *mrcp) {
    assert(mrcp);

    if (mrcp->pool) {
        apr_pool_destroy(mrcp->pool);
    }

    return APR_SUCCESS;
}

sipdump_mrcp_message_type_e sipdump_mrcp_message_type_get(const sipdump_mrcp_t *mrcp) {
    assert(mrcp);
    return mrcp->request_line.type;
}

sipdump_mrcp_code sipdump_mrcp_code_get(const sipdump_mrcp_t *mrcp) {
    assert(mrcp);
    return mrcp->request_line.message.response.code;
}

sipdump_mrcp_event_e sipdump_mrcp_event_get(const sipdump_mrcp_t *mrcp) {
    assert(mrcp);
    return mrcp->request_line.message.event.event;
}

sipdump_mrcp_request_state_e sipdump_mrcp_request_state_get(const sipdump_mrcp_t *mrcp) {
    assert(mrcp);
    switch (mrcp->request_line.type) {
        case SIPDUMP_MRCP_MSG_TYPE_RESPONSE:
            return mrcp->request_line.message.response.request_state;
        case SIPDUMP_MRCP_MSG_TYPE_EVENT:
            return mrcp->request_line.message.event.request_state;
    }
    return SIPDUMP_MRCP_REQUEST_STATE_UNKNOWN;
}

sipdump_mrcp_request_e sipdump_mrcp_request_get(const sipdump_mrcp_t *mrcp) {
    assert(mrcp);
    return mrcp->request_line.message.request.method;
}

const sipdump_string_t *sipdump_mrcp_hdr_get(const sipdump_mrcp_t *mrcp, sipdump_string_t *hdr) {
    assert(mrcp);
    assert(hdr);
    return apr_hash_get(mrcp->hdr.hdrs, hdr->str, hdr->len);
}

apr_hash_t *sipdump_mrcp_hdrs_get(const sipdump_mrcp_t *mrcp) {
    assert(mrcp);
    return mrcp->hdr.hdrs;
}

void sipdump_mrcp_show_message(const sipdump_mrcp_t *mrcp, const char *prefix) {
    assert(mrcp);

    switch (mrcp->request_line.type) {
        case SIPDUMP_MRCP_MSG_TYPE_REQUEST:
            SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s MRCP REQUEST  [%u] %s", 
                prefix, 
                mrcp->request_line.request_id, 
                mrcp->request_line.message.request.method_name);
            break;

        case SIPDUMP_MRCP_MSG_TYPE_RESPONSE:
            SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s MRCP RESPONSE [%u] %d (%s)", 
                prefix, 
                mrcp->request_line.request_id, 
                mrcp->request_line.message.response.code, 
                mrcp->request_line.message.response.request_state_name);
            break;

        case SIPDUMP_MRCP_MSG_TYPE_EVENT:
            SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s MRCP EVENT    [%u] %s (%s)", 
                prefix, 
                mrcp->request_line.request_id, 
                mrcp->request_line.message.event.event_name, 
                mrcp->request_line.message.event.request_state_name);
            break;
        
        default:
            break;
    }
}