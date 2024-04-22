#include <apr.h>

#include "sipdump_module.h"
#include "sipdump_hook.h"
#include "sipdump_log.h"

static void sip_message(
    sipdump_session_t *session, 
    sipdump_sip_method_e method, 
    sipdump_sip_code code, 
    sipdump_sip_hdr_common_t *hdrs,
    apr_uint32_t hdr_count,
    const char *data, 
    apr_size_t size
) {
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s PLUGIN %u %u %u", 
        sipdump_session_uuid_get(session),
        method, code, hdr_count
    );
}

static void session_print(
    sipdump_session_t *session,
    const char **data
) {
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "%s PLUGIN print", 
        sipdump_session_uuid_get(session)
    );
    *data = "PLUGIN example sip print";
}

static apr_status_t load(apr_pool_t *pool, sipdump_module_t *module) {
    sipdump_hook_sip_message(module, sip_message);
    sipdump_hook_session_print(module, session_print);
    return APR_SUCCESS;
}

static apr_status_t unload() {
    return APR_SUCCESS;
}

SIPDUMP_DECLARE_MODULE(example_sip) = {
    SIPDUMP_MODULE_STUFF,
    "example_sip",
    load,
    unload,
    0
};