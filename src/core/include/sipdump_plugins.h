#ifndef SIPDUMP_PLUGINS_H__
#define SIPDUMP_PLUGINS_H__

#include <apr.h>

#include "sipdump_opt.h"
#include "sipdump_hook.h"

APR_BEGIN_DECLS

apr_status_t sipdump_plugins_init();
apr_status_t sipdump_plugins_uninit();
void sipdump_plugins_module_dir_set(const char *dir);
apr_status_t sipdump_plugins_module_add(const char *id, const char *name, apr_uint32_t enable);
void sipdump_plugins_hook_sip_message_set(sipdump_module_t *imodule, sipdump_hook_sip_message_f *fun);
void sipdump_plugins_hook_sip_message_do(
    sipdump_session_t *session, 
    sipdump_sip_method_e method, 
    sipdump_sip_code code, 
    sipdump_sip_hdr_common_t *hdrs,
    apr_uint32_t hdr_count,
    const char *data, 
    apr_size_t size
);
#ifdef SIPDUMP_MRCP
void sipdump_plugins_hook_mrcp_message_set(sipdump_module_t *imodule, sipdump_hook_mrcp_message_f *fun);
void sipdump_plugins_hook_mrcp_message_do(
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
#endif
void sipdump_plugins_hook_session_print_set(sipdump_module_t *imodule, sipdump_hook_session_print_f *fun);
const char *sipdump_plugins_hook_session_print_do(sipdump_session_t *session);

void sipdump_plugins_hook_record_rename_set(sipdump_module_t *imodule, sipdump_hook_record_rename_f *fun);
const char *sipdump_plugins_hook_record_rename_do(sipdump_session_t *session);



APR_END_DECLS

#endif