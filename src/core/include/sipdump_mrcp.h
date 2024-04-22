#ifndef SIPDUMP_MRCP_H__
#define SIPDUMP_MRCP_H__

#include <apr.h>

APR_BEGIN_DECLS

#define SIPDUMP_MRCP_PKT_LEN_MIN 32

enum sipdump_mrcp_request_e {
    SIPDUMP_MRCP_REQUEST_UNKNOWN, /**< Invalid method name */
    SIPDUMP_MRCP_REQUEST_SET_PARAMS, /**< SET-PARAMS */
    SIPDUMP_MRCP_REQUEST_GET_PARAMS, /**< GET-PARAMS */
    SIPDUMP_MRCP_REQUEST_DEFINE_GRAMMAR, /**< DEFINE-GRAMMAR */
    SIPDUMP_MRCP_REQUEST_RECOGNIZE, /**< RECOGNIZE */
    SIPDUMP_MRCP_REQUEST_INTERPRET, /**< INTERPRET */
    SIPDUMP_MRCP_REQUEST_GET_RESULT, /**< GET-RESULT */
    SIPDUMP_MRCP_REQUEST_START_INPUT_TIMERS, /**< START-INPUT-TIMERS */
    SIPDUMP_MRCP_REQUEST_STOP, /**< STOP */
    SIPDUMP_MRCP_REQUEST_START_PHRASE_ENROLLMENT, /**< START-PHRASE-ENROLLMENT */
    SIPDUMP_MRCP_REQUEST_ENROLLMENT_ROLLBACK, /**< ENROLLMENT-ROLLBACK */
    SIPDUMP_MRCP_REQUEST_END_PHRASE_ENROLLMENT, /**< END-PHRASE-ENROLLMENT */
    SIPDUMP_MRCP_REQUEST_MODIFY_PHRASE, /**< MODIFY-PHRASE */
    SIPDUMP_MRCP_REQUEST_DELETE_PHRASE, /**< DELETE-PHRASE */
};
typedef enum sipdump_mrcp_request_e sipdump_mrcp_request_e;

enum sipdump_mrcp_request_state_e {
    SIPDUMP_MRCP_REQUEST_STATE_UNKNOWN, /**< Invalid request state */
    SIPDUMP_MRCP_REQUEST_STATE_COMPLETE, /**< COMPLETE */
    SIPDUMP_MRCP_REQUEST_STATE_IN_PROGRESS, /**< IN-PROGRESS */
    SIPDUMP_MRCP_REQUEST_STATE_PENDING, /**< PENDING */
};
typedef enum sipdump_mrcp_request_state_e sipdump_mrcp_request_state_e;

enum sipdump_mrcp_event_e {
    SIPDUMP_MRCP_EVENT_UNKNOWN, /**< Invalid event name */
    SIPDUMP_MRCP_EVENT_START_OF_INPUT, /**< START-OF-INPUT */
    SIPDUMP_MRCP_EVENT_RECOGNITION_COMPLETE, /**< RECOGNITION-COMPLETE */
    SIPDUMP_MRCP_EVENT_INTERPRETATION_COMPLETE, /**< INTERPRETATION-COMPLETE */
};
typedef enum sipdump_mrcp_event_e sipdump_mrcp_event_e;

typedef unsigned int sipdump_mrcp_code;

enum sipdump_mrcp_message_type_e {
    SIPDUMP_MRCP_MSG_TYPE_UNKNOWN,
    SIPDUMP_MRCP_MSG_TYPE_REQUEST,
    SIPDUMP_MRCP_MSG_TYPE_RESPONSE,
    SIPDUMP_MRCP_MSG_TYPE_EVENT,
};
typedef enum sipdump_mrcp_message_type_e sipdump_mrcp_message_type_e;

typedef struct sipdump_mrcp_t sipdump_mrcp_t;

apr_status_t sipdump_mrcp_parse(const char *data, apr_size_t size, sipdump_mrcp_t **mrcp);
apr_status_t sipdump_mrcp_free(const sipdump_mrcp_t *mrcp);

sipdump_mrcp_message_type_e sipdump_mrcp_message_type_get(const sipdump_mrcp_t *mrcp);
sipdump_mrcp_code sipdump_mrcp_code_get(const sipdump_mrcp_t *mrcp);
sipdump_mrcp_event_e sipdump_mrcp_event_get(const sipdump_mrcp_t *mrcp);
sipdump_mrcp_request_state_e sipdump_mrcp_request_state_get(const sipdump_mrcp_t *mrcp);
sipdump_mrcp_request_e sipdump_mrcp_request_get(const sipdump_mrcp_t *mrcp);

const sipdump_string_t *sipdump_mrcp_hdr_get(const sipdump_mrcp_t *mrcp, sipdump_string_t *hdr);
apr_hash_t *sipdump_mrcp_hdrs_get(const sipdump_mrcp_t *mrcp);
void sipdump_mrcp_show_message(const sipdump_mrcp_t *mrcp, const char *prefix);

APR_END_DECLS

#endif