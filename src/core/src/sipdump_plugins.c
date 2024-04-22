#include <assert.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_ring.h>
#include <apr_dso.h>

#include "sipdump_config.h"
#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_opt.h"
#include "sipdump_module.h"
#include "sipdump_plugins.h"
#include "sipdump_hook.h"

struct sipdump_internal_module_t {
    APR_RING_ENTRY(sipdump_internal_module_t) link;
    apr_pool_t *pool;
    const char *id;
    const char *name;
    apr_uint32_t enable;
    apr_uint32_t loaded;
    sipdump_module_t *module;
    apr_dso_handle_t *dso;

    /** hook */
    struct {
        sipdump_hook_sip_message_f *sip_message;
#ifdef SIPDUMP_MRCP
        sipdump_hook_mrcp_message_f *mrcp_message;
#endif
        sipdump_hook_session_print_f *session_print;
        sipdump_hook_record_rename_f *record_rename;
    } hook;
};

struct sipdump_plugins_t {
    apr_pool_t *pool;
    const char* dir;
    APR_RING_HEAD(sipdump_module_list_t, sipdump_internal_module_t) modules;
} plugins;

apr_status_t sipdump_plugins_init() {
    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, NULL);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "Plugin create pool error: %d", status);
        return status;
    }

    plugins.pool = pool;
    APR_RING_INIT(&plugins.modules, sipdump_internal_module_t, link);

    return APR_SUCCESS;
}


apr_status_t sipdump_plugins_module_remove(struct sipdump_internal_module_t* imodule) {
    assert(imodule);
    APR_RING_REMOVE(imodule, link);
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "Plugin '%s' removed", imodule->name);
    if (imodule->module->unload) {
        imodule->module->unload();
    }
    if (imodule->dso) {
        apr_dso_unload(imodule->dso);
    }
    if (imodule->pool) {
        apr_pool_destroy(imodule->pool);
    }
}

apr_status_t sipdump_plugins_uninit() {

    struct sipdump_internal_module_t *imodule = NULL;
    struct sipdump_internal_module_t *next = NULL;
    APR_RING_FOREACH_SAFE(imodule, next, &plugins.modules, sipdump_internal_module_t, link) {
        sipdump_plugins_module_remove(imodule);
    }

    if (plugins.pool) {
        apr_pool_destroy(plugins.pool);
    }

    return APR_SUCCESS;
}

void sipdump_plugins_module_dir_set(const char *dir) {
    assert(dir);
    plugins.dir = apr_pstrdup(plugins.pool, dir);
}

apr_status_t sipdump_plugins_module_add(const char *id, const char *name, apr_uint32_t enable) {
    assert(id);
    assert(name);

    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, NULL);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "Plugin '%s' Create pool error. code: %u", name, status);
        return status;
    }

    char path[256] = {'\0'};
    snprintf(path, sizeof(path), "%s/%s.so", plugins.dir, name);
    apr_dso_handle_t *dso = NULL;
    status = apr_dso_load(&dso, path, pool);
    if (status != APR_SUCCESS) {
        char error[256];
        SIPDUMP_LOG(SIPDUMP_PRIO_WARNING, "Plugin '%s' load error. path: %s, code: %u, reason: %s",
            name, path, status, apr_dso_error(dso, error, sizeof(error)));
        apr_pool_destroy(pool);
        return status;
    }

    apr_dso_handle_sym_t sym;
    char sym_name[256] = {'\0'};
    snprintf(sym_name, sizeof(sym_name), "%s_module", name);
    status = apr_dso_sym(&sym, dso, sym_name);
    if (status != APR_SUCCESS) {
        char error[256];
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "Plugin '%s' load error. reason: %s", 
            name, apr_dso_error(dso, error, sizeof(error)));
        apr_dso_unload(dso);
        apr_pool_destroy(pool);
        return status;
    }

    struct sipdump_internal_module_t *imodule = apr_pcalloc(pool, sizeof(struct sipdump_internal_module_t));
    APR_RING_ELEM_INIT(imodule, link);
    imodule->pool = pool;
    imodule->id = apr_pstrdup(imodule->pool, id);
    imodule->name = apr_pstrdup(imodule->pool, name);
    imodule->enable = enable;
    imodule->module = apr_pmemdup(pool, sym, sizeof(sipdump_module_t));
    imodule->module->module = imodule;
    imodule->dso = dso;

    if (imodule->module->magic != SIPDUMP_MODULE_MAGIC_COOKIE) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "Plugin '%s' load error. reason: magic %lu != %lu", imodule->module->magic, SIPDUMP_MODULE_MAGIC_COOKIE); 
        apr_dso_unload(dso);
        apr_pool_destroy(pool);
        return status;
    }

    if (imodule->enable) {
        if (imodule->module->load) {
            status = imodule->module->load(imodule->pool, imodule->module);
            if (status != APR_SUCCESS) {
                SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "Plugin '%s' load error. code: %d", name, status); 
                apr_dso_unload(dso);
                apr_pool_destroy(pool);
                return status;
            }
            imodule->loaded = TRUE;
            APR_RING_INSERT_TAIL(&plugins.modules, imodule, sipdump_internal_module_t, link);
            SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "Plugin '%s' added", name); 
        }
    } else {
        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "Plugin '%s' has disabled", name);
    }

    return APR_SUCCESS;
}

void sipdump_plugins_hook_sip_message_do(
    sipdump_session_t *session, 
    sipdump_sip_method_e method, 
    sipdump_sip_code code, 
    sipdump_sip_hdr_common_t *hdrs,
    apr_uint32_t hdr_count,
    const char *data, 
    apr_size_t size
) {
    struct sipdump_internal_module_t *imodule = NULL;
    APR_RING_FOREACH(imodule, &plugins.modules, sipdump_internal_module_t, link) {
        if (imodule->hook.sip_message) {
            imodule->hook.sip_message(session, method, code, hdrs, hdr_count, data, size);
        }
    }
}

void sipdump_plugins_hook_sip_message_set(sipdump_module_t *imodule, sipdump_hook_sip_message_f *fun) {
    assert(imodule);
    struct sipdump_internal_module_t *m  = imodule->module;
    m->hook.sip_message = fun;
}
#ifdef SIPDUMP_MRCP
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
) {
    struct sipdump_internal_module_t *imodule = NULL;
    APR_RING_FOREACH(imodule, &plugins.modules, sipdump_internal_module_t, link) {
        if (imodule->hook.mrcp_message) {
            imodule->hook.mrcp_message(session, type, request, state, event, code, hdrs, data, size);
        }
    }
}
void sipdump_plugins_hook_mrcp_message_set(sipdump_module_t *imodule, sipdump_hook_mrcp_message_f *fun) {
    assert(imodule);
    struct sipdump_internal_module_t *m  = imodule->module;
    m->hook.mrcp_message = fun;
}
#endif
const char *sipdump_plugins_hook_session_print_do(sipdump_session_t *session) {
    struct sipdump_internal_module_t *imodule = NULL;
    apr_pool_t *pool = sipdump_session_pool_get(session);
    char* buffer = "";

    APR_RING_FOREACH(imodule, &plugins.modules, sipdump_internal_module_t, link) {
        if (imodule->hook.session_print) {
            const char* p = NULL;
            imodule->hook.session_print(session, &p);
            if (p) {
                buffer = apr_pstrcat(pool, buffer, p, NULL);
            }
        }
    }
    return buffer;
}
void sipdump_plugins_hook_session_print_set(sipdump_module_t *imodule, sipdump_hook_session_print_f *fun) {
    assert(imodule);
    struct sipdump_internal_module_t *m  = imodule->module;
    m->hook.session_print = fun;
}

const char *sipdump_plugins_hook_record_rename_do(sipdump_session_t *session) {
    struct sipdump_internal_module_t *imodule = NULL;
    const char *name = NULL;
    APR_RING_FOREACH(imodule, &plugins.modules, sipdump_internal_module_t, link) {
        if (imodule->hook.record_rename) {
            imodule->hook.record_rename(session, &name);
        }
    }

    return name;
}

void sipdump_plugins_hook_record_rename_set(sipdump_module_t *imodule, sipdump_hook_record_rename_f *fun) {
    assert(imodule);
    struct sipdump_internal_module_t *m  = imodule->module;
    m->hook.record_rename = fun;
}