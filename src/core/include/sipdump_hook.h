#ifndef SIPDUMP_HOOK_H__
#define SIPDUMP_HOOK_H__

#include <apr.h>
#include <apr_errno.h>
#include <apr_pools.h>
#include <apr_hash.h>

#include "sipdump_sip.h"
#include "sipdump_mrcp.h"
#include "sipdump_module.h"
#include "sipdump_session.h"

APR_BEGIN_DECLS

typedef void sipdump_hook_sip_message_f(
    sipdump_session_t *session, 
    sipdump_sip_method_e method, 
    sipdump_sip_code code, 
    sipdump_sip_hdr_common_t *hdrs,
    apr_uint32_t hdr_count,
    const char *data, 
    apr_size_t size
);
void sipdump_hook_sip_message(sipdump_module_t *module, sipdump_hook_sip_message_f* fun);

#ifdef SIPDUMP_MRCP
typedef void sipdump_hook_mrcp_message_f(
    sipdump_session_t *session, 
    sipdump_mrcp_message_type_e type, 
    sipdump_mrcp_request_e request, 
    sipdump_mrcp_request_state_e state, 
    sipdump_mrcp_event_e event, 
    sipdump_mrcp_code code, 
    apr_hash_t *hdrs, 
    const char *data, 
    apr_size_t size
);
void sipdump_hook_mrcp_message(sipdump_module_t *module, sipdump_hook_mrcp_message_f* fun);
#endif

typedef void sipdump_hook_session_print_f(
    sipdump_session_t *session,
    const char** data
);
void sipdump_hook_session_print(sipdump_module_t *module, sipdump_hook_session_print_f* fun);

typedef void sipdump_hook_record_rename_f(
    sipdump_session_t *session,
    const char** name
);
void sipdump_hook_record_rename(sipdump_module_t *module, sipdump_hook_record_rename_f* fun);

APR_END_DECLS

#endif