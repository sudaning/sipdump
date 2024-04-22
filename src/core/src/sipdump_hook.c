#include <assert.h>
#include <string.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_plugins.h"
#include "sipdump_module.h"
#include "sipdump_hook.h"

void sipdump_hook_sip_message(sipdump_module_t *module, sipdump_hook_sip_message_f* fun) {
    sipdump_plugins_hook_sip_message_set(module, fun);
}

#ifdef SIPDUMP_MRCP
void sipdump_hook_mrcp_message(sipdump_module_t *module, sipdump_hook_mrcp_message_f* fun) {
    sipdump_plugins_hook_mrcp_message_set(module, fun);
}
#endif

void sipdump_hook_session_print(sipdump_module_t *module, sipdump_hook_session_print_f* fun) {
    sipdump_plugins_hook_session_print_set(module, fun);
}

void sipdump_hook_record_rename(sipdump_module_t *module, sipdump_hook_record_rename_f* fun) {
    sipdump_plugins_hook_record_rename_set(module, fun);
}