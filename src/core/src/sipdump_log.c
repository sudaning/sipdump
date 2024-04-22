#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include "sipdump_config.h"
#include "sipdump_util.h"
#include "sipdump_log.h"

int g_priority = SIPDUMP_PRIO_INFO;

int g_syslog = FALSE;
void *g_facility = FALSE;

apr_status_t sipdump_log_init(const char *name, const char* mod, void* facility) {

#ifdef SIPDUMP_USE_SYS_LOG
    if (mod && !strcmp(mod, "syslog")) {
        g_syslog = TRUE;
    }
    openlog(name, LOG_CONS|LOG_PID, (int)facility);
#endif
    g_facility = facility;
    return APR_SUCCESS;
}

apr_status_t sipdump_log_uninit() {
#ifdef SIPDUMP_USE_SYS_LOG
    closelog();
#endif
}

sipdump_log_priority_e sipdump_log_priority_set(const char *priority) {
    sipdump_log_priority_e pro = SIPDUMP_PRIO_INFO;
    if (!strncasecmp(priority, "TRACE", sizeof("TRACE") - 1)) {
        pro = SIPDUMP_PRIO_TRACE;
    } else if (!strncasecmp(priority, "DEBUG", sizeof("DEBUG") - 1)) {
        pro = SIPDUMP_PRIO_DEBUG;
    } else if (!strncasecmp(priority, "INFO", sizeof("INFO") - 1)) {
        pro = SIPDUMP_PRIO_INFO;
    } else if (!strncasecmp(priority, "NOTICE", sizeof("NOTICE") - 1)) {
        pro = SIPDUMP_PRIO_NOTICE;
    } else if (!strncasecmp(priority, "WARN", sizeof("WARN") - 1)) {
        pro = SIPDUMP_PRIO_WARNING;
    } else if (!strncasecmp(priority, "ERROR", sizeof("ERROR") - 1)) {
        pro = SIPDUMP_PRIO_ERROR;
    } else if (!strncasecmp(priority, "CRIT", sizeof("CRIT") - 1)) {
        pro = SIPDUMP_PRIO_CRITICAL;
    } else {
        pro = SIPDUMP_PRIO_INFO;
    }
    g_priority = pro;
    return g_priority;
}

int sipdump_log_priority_trace() {
    return g_priority >= SIPDUMP_PRIO_TRACE;
}

void sipdump_log(const char *file, int line, sipdump_log_priority_e priority, const char *fmt, ...) {
    char log_entry[4096] = {'\0'};
    int max_size = sizeof(log_entry) - 2;
    int offset = 0;

#ifdef SIPDUMP_USE_SYS_LOG
    int log_level = 0;
    if (g_syslog) {
        switch (priority) {
            case SIPDUMP_PRIO_CRITICAL: log_level = LOG_CRIT; break;
            case SIPDUMP_PRIO_ERROR: log_level = LOG_ERR; break;
            case SIPDUMP_PRIO_WARNING: log_level = LOG_WARNING; break;
            case SIPDUMP_PRIO_NOTICE: log_level = LOG_NOTICE; break;
            case SIPDUMP_PRIO_INFO: log_level = LOG_INFO; break;
            case SIPDUMP_PRIO_DEBUG: log_level = LOG_DEBUG; break;
            case SIPDUMP_PRIO_TRACE: log_level = LOG_DEBUG; break;
            default:
                break;
        }
    } else 
#endif
    {
        char log_level_str = '\0';
        switch (priority) {
            case SIPDUMP_PRIO_CRITICAL: log_level_str = 'C'; break;
            case SIPDUMP_PRIO_ERROR: log_level_str = 'E'; break;
            case SIPDUMP_PRIO_WARNING: log_level_str = 'W'; break;
            case SIPDUMP_PRIO_NOTICE: log_level_str = 'N'; break;
            case SIPDUMP_PRIO_INFO: log_level_str = 'I'; break;
            case SIPDUMP_PRIO_DEBUG: log_level_str = 'D'; break;
            case SIPDUMP_PRIO_TRACE: log_level_str = 'T'; break;
            default:
                break;
        }
        log_entry[0] = log_level_str;
        log_entry[1] = ' ';
        offset = 2;

        /** time */
        offset += sipdump_timestamp_snprintf(apr_time_now(), log_entry + offset, max_size - offset);
    }


    /** file and line */
    // offset += snprintf(log_entry + offset, max_size - offset, "%s:%u ", file, line);

    /** content */
    va_list args;
    va_start(args, fmt);
    offset += apr_vsnprintf(log_entry + offset, max_size - offset, fmt, args);
    va_end(args);

    /** endline */
    log_entry[offset++] = '\n';
	log_entry[offset] = '\0';
#ifdef SIPDUMP_USE_SYS_LOG
    if (g_syslog) {
        syslog(log_level, log_entry);
    } else
#endif
    {
        if (g_facility) {
            fprintf((FILE*)g_facility, log_entry);
        } else {
            fprintf(stdout, log_entry);
        }
    }
}
