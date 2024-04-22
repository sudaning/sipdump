#include <apr.h>
#include <apr_strings.h>

#include "sipdump_module.h"
#include "sipdump_hook.h"
#include "sipdump_log.h"

struct mrcp_t {
    sipdump_string_t vsp;
};

static void mrcp_message(
    sipdump_session_t *session, 
    sipdump_mrcp_message_type_e type, 
    sipdump_mrcp_request_e request, 
    sipdump_mrcp_request_state_e state, 
    sipdump_mrcp_event_e event, 
    sipdump_mrcp_code code, 
    apr_hash_t *hdrs, 
    const char *data, 
    apr_size_t size
) {
    if (type == SIPDUMP_MRCP_MSG_TYPE_REQUEST && request == SIPDUMP_MRCP_REQUEST_RECOGNIZE) {
        sipdump_string_t *v = apr_hash_get(hdrs, "Vendor-Specific-Parameters", sizeof("Vendor-Specific-Parameters") - 1);
        if (v) {
            apr_pool_t *pool = sipdump_session_pool_get(session);
            struct mrcp_t *my_mrcp = apr_pcalloc(pool, sizeof(struct mrcp_t));
            my_mrcp->vsp.str = apr_pstrndup(pool, v->str, v->len);
            my_mrcp->vsp.len = v->len;
            sipdump_session_plugin_user_data_set(session, my_mrcp);
        }
    }
}

static void session_print(
    sipdump_session_t *session,
    const char** data
) {
    struct mrcp_t *my_mrcp = sipdump_session_plugin_user_data_get(session);
    if (my_mrcp) {
        apr_pool_t *pool = sipdump_session_pool_get(session);
        *data = apr_pstrcat(pool, "MRCP Vendor-Specific-Parameters: ", my_mrcp->vsp.str, NULL);
    }
}

static void record_rename(
    sipdump_session_t *session,
    const char** name
) {
    struct mrcp_t *my_mrcp = sipdump_session_plugin_user_data_get(session);
    if (!my_mrcp) {
        *name = NULL;
        return;
    }

    apr_pool_t *pool = sipdump_session_pool_get(session);
    *name = apr_psprintf(pool, "%s", my_mrcp->vsp.str);
}

static apr_status_t load(apr_pool_t *pool, sipdump_module_t *module) {
    sipdump_hook_mrcp_message(module, mrcp_message);
    sipdump_hook_session_print(module, session_print);
    sipdump_hook_record_rename(module, record_rename);
    return APR_SUCCESS;
}

static apr_status_t unload() {
    return APR_SUCCESS;
}

SIPDUMP_DECLARE_MODULE(example_mrcp) = {
    SIPDUMP_MODULE_STUFF,
    "example_mrcp",
    load,
    unload,
    0
};