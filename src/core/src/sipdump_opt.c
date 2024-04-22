#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <regex.h>
#include <string.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_network_io.h>
#include <apr_hash.h>
#include <apr_xml.h>

#include "sipdump_config.h"
#include "sipdump_plugins.h"
#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_sip.h"
#include "sipdump_opt.h"

struct sipdump_number_filter_t {
    int used; /** 是否使用 */
    sipdump_string_t org_str; /** 原始字符串 */
    regex_t regex; /** 编译出的正则 */
};
/** 号码过滤器（from, to等头域中的号码） */
typedef struct sipdump_number_filter_t sipdump_number_filter_t;

#define METHOD_FILTER_MAX 16 /** SIP方法支持最大过滤个数 */
struct sipdump_sip_method_filter_t {
    int used; /** 是否使用 */
    sipdump_string_t org_str; /** 原始字符串 */
    int num; /** 方法个数 */
    int methods[METHOD_FILTER_MAX]; /** 方法数组 */
};
/** SIP方法过滤器 */
typedef struct sipdump_sip_method_filter_t sipdump_sip_method_filter_t;

struct sipdump_sip_rtp_filter_t {
    sipdump_string_t org_str; /** 原始字符串 */
    int types; /** RTP类型组合 */
};
/** RTP过滤器 */
typedef struct sipdump_sip_rtp_filter_t sipdump_sip_rtp_filter_t;

struct sipdump_ipgroup_t {
    apr_hash_t *hash;
};
/** IP组 */
typedef struct sipdump_ipgroup_t sipdump_ipgroup_t;

#define PCAP_FILTER_EXPRESSION 1024 /** 网卡过滤表达式的最大字符长度 */
/** 配置 */
struct sipdump_opt_t {
    apr_pool_t *pool; /** 内存池 */
    const char *record_path; /** 存储位置 */
    const char *pid_file; /** pid文件 */
    apr_int64_t limit_time; /** 会话超时时间 */

    int log_priority; /** 日志输出等级 */
    const char *log_name;
    const char *log_mode;
    void* log_facility;

    /** 配置文件 */
    const char *cfg_path;

    /** 读取数据（二选一） */
    const char *eth_name; /** 从网卡里读取数据包（优先于pcap文件中读取） */
    const char *pcap_name; /** 从pcap文件中读取包（网卡读包优先） */

    /** 网卡设置 */
    const char *pcap_filter; /** 网卡过滤表达式 */
    int pcap_promisc; /** 网卡抓包混杂模式，默认0 */
    int pcap_buffer_size; /** libpcap ring buffer大小，默认0，不设置 */
    int pcap_flush; /** 抓包之后，筛选出目标包，是否立即刷新到文件中，默认1 */
    
    /** 过滤 */
    sipdump_number_filter_t number_filter; /** 号码过滤 */
    sipdump_sip_method_filter_t sip_method_filter; /** SIP方法过滤 */
    sipdump_sip_rtp_filter_t rtp_filter; /** RTP方法过滤 */

    /** ip组 */
    sipdump_ipgroup_t ipgroup;
};

apr_status_t sipdump_opt_create(sipdump_opt_t **opt) {
    assert(opt);

    apr_pool_t *pool = NULL;
    apr_status_t status = apr_pool_create(&pool, NULL);
    if (status != APR_SUCCESS) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "create pool error: %d", status);
        return status;
    }

    sipdump_opt_t *o = apr_pcalloc(pool, sizeof(sipdump_opt_t));
    if (!o) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "pcalloc from pool error");
        return APR_ENOMEM;
    }

    o->pool = pool;

    o->log_mode = NULL;
    o->log_facility = 0;
    o->log_priority = 0;

    o->eth_name = NULL;
    o->pcap_name = NULL;

    o->number_filter.used = 0;
    o->number_filter.org_str.str = NULL;
    o->number_filter.org_str.len = 0;

    o->sip_method_filter.used = TRUE;
    o->sip_method_filter.org_str.str = "INVITE";
    o->sip_method_filter.org_str.len = sizeof("INVITE") - 1;
    o->sip_method_filter.num = 1;
    o->sip_method_filter.methods[0] = SIPDUMP_SIP_METHOD_INVITE;

    o->pcap_promisc = TRUE;
    o->rtp_filter.org_str.str = NULL;
    o->rtp_filter.org_str.len = 0;
    o->rtp_filter.types = SIPDUMP_RTP_CAPTURE_NONE;
    o->pcap_buffer_size = 0;
    o->pcap_flush = TRUE;
    o->limit_time = 7200;
    o->pid_file = apr_pstrdup(pool, SIPDUMP_PID_FILE);
    o->record_path = apr_pstrdup(pool, SIPDUMP_RECORD_PATH);

    *opt = o;
    return APR_SUCCESS;
}

apr_status_t sipdump_opt_destroy(sipdump_opt_t *opt) {
    assert(opt);
    if (opt->pool) {
        apr_pool_destroy(opt->pool);
    }
    return APR_SUCCESS;
}

apr_status_t sipdump_opt_cmd_parse(sipdump_opt_t *opt, int argc, char *argv[]) {
    assert(opt);

    while(1) {
        /** 输出参数，可覆盖配置文件中的配置 */
        int c = getopt(argc, argv, "c:i:r:v:m:n:d:R:B:P:T:pU");
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'c':
                sipdump_opt_config_load(opt, optarg);
                break;
            case 'i':
                sipdump_opt_eth_name_set(opt, optarg);
                break;
            case 'r':
                sipdump_opt_pcap_name_set(opt, optarg);
                break;
            case 'v':
                sipdump_opt_log_priority_set(opt, optarg);
                break;
            case 'm':
                sipdump_opt_sip_method_filter_set(opt, optarg);
                break;
            case 'n':
                sipdump_opt_number_filter_set(opt, optarg);
                break;
            case 'd':
                sipdump_opt_pcap_record_path_set(opt, optarg);
                break;
            case 'R':
                sipdump_opt_rtp_filter_set(opt, optarg);
                break;
            case 'B': {
                int pcap_buffer_size = sipdump_size_string_parse(optarg);
                if (pcap_buffer_size < 0){
                    SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "Invalid option '-B %s'.\n"
                                    "  Argument should be positive integer with optional quantifier.\n"
                                    "  e.g.: '-B 32768' or '-B 10KB' or '-B 512MB', etc.", optarg);
                    return APR_BADARG;
                }
                sipdump_opt_pcap_buffer_size_set(opt, pcap_buffer_size);
                break;
            }
            case 'T':
                sipdump_opt_limit_time_set(opt, apr_atoi64(optarg));
                break;
            case 'P':
                sipdump_opt_pid_file_set(opt, optarg);
                break;
            case 'p':
                sipdump_opt_promisc_set(opt, 0);
                break;
            case 'U':
                sipdump_opt_pcap_flush_set(opt, 0);
                break;
        }
    }

    if (!opt->eth_name && !opt->pcap_name) {
        SIPDUMP_LOG(SIPDUMP_PRIO_ERROR, "OPT must be input 'ether name' or 'pcap name'"); 
        return APR_EINVAL;
    }

    // everything that is left unparsed in argument string is pcap filter expression
    if (optind < argc) {
        char filter_exp[PCAP_FILTER_EXPRESSION] = {'\0'}; 
        while (optind < argc) {
            if (filter_exp[0] != '\0') {
                strcat(filter_exp, " ");
            }
            strcat(filter_exp, argv[optind++]);
        }
        sipdump_opt_pcap_filter_set(opt, filter_exp);
    }

    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT log_mode: %s", opt->log_mode); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT log_facility: %u", opt->log_facility); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT log_priority: %u", opt->log_priority); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT pid_file: %s", opt->pid_file); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT limit_time: %u", opt->limit_time); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT eth_name: %s", opt->eth_name); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT pcap_name: %s", opt->pcap_name); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT pcap_filter: %s", opt->pcap_filter); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT pcap_promisc: %u", opt->pcap_promisc); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT pcap_buffer_size: %u", opt->pcap_buffer_size); 
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT pcap_flush: %s", SIPDUMP_YESNO(opt->pcap_flush));
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT record_path: %s", opt->record_path);
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT sip_number_filter.used: %s", SIPDUMP_YESNO(opt->number_filter.used));
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT sip_number_filter.regex: %s", opt->number_filter.org_str.str);
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT sip_method_filter.used: %s", SIPDUMP_YESNO(opt->sip_method_filter.used));
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT sip_method_filter.str: %s", opt->sip_method_filter.org_str.str);
    SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT rtp_filter: [rtp:%s] [rtcp:%s] [event:%s]", 
        SIPDUMP_YESNO(sipdump_opt_rtp_filter_test(opt, SIPDUMP_RTP_CAPTURE_RTP)),
        SIPDUMP_YESNO(sipdump_opt_rtp_filter_test(opt, SIPDUMP_RTP_CAPTURE_RTCP)),
        SIPDUMP_YESNO(sipdump_opt_rtp_filter_test(opt, SIPDUMP_RTP_CAPTURE_RTP_EVENT))
    );
    return APR_SUCCESS;
}

const char *sipdump_opt_cmd_usage(const char* exec_name) {

    static char usage[2048] = {'\0'};
    snprintf(usage, sizeof(usage), 
        "Usage: %s [-pU] [-i interface | -r file] [-P pid_file]\n"
                "                   [-v level] [-R filter] [-m filter] [-n filter]\n"
                "                   [-B size] [-T timeout] [expression]\n"
        " -i   Specify network interface name (i.e. eth0, em1, ppp0, etc).\n"
        " -r   Read from .pcap file instead of network interface.\n"
        " -P   When forking, save PID to this file (default " SIPDUMP_PID_FILE ").\n"
        " -p   Do not put the interface into promiscuous mode.\n"
        " -U   Make .pcap files writing 'packet-buffered' - slower method,\n"
        "      but you can use partitially written file anytime, it will be consistent.\n"
        " -d   Set directory (or filename template), where captured files will be stored.\n"
        " -v   Set log level (higher is more verbose).\n"
        " -B   Set the operating system capture buffer size, a.k.a. ring buffer size.\n"
        "      This can be expressed in B(*1)/KB(*1024)/MB(*1024*1024)/GB(*1024*1024*1024). ex.: '-B 64MB'\n"
        "      Set this to few MiB or more to avoid packets dropped by kernel.\n"
        " -R   RTP filter. Specifies what kind of RTP information to include in capture:\n"
        "      'all', 'rtp|rtcp|rtpevent', or 'none' (default).\n"
        " -m   Method-filter. Default is 'INVITE', example: 'INVITE|REGISTER'\n"
        " -n   Number-filter. Only calls to/from specified number will be recorded\n"
        "      Argument is a regular expression. See 'man 7 regex' for details.\n"
        " -T   Unconditionally stop recording a call after it was active for this many seconds.\n"
        "      Might be useful for broken peers that keep sending RTP long after call ended.\n"
        " -h   For help.\n"
        " -V   Version.\n"
        "\n", exec_name);
     return usage;
}

static apr_status_t sipdump_opt_config_ipgroup_load(sipdump_opt_t *opt, apr_xml_elem *ipgroup) {
    assert(opt);
    assert(ipgroup);

    apr_hash_t *hash = apr_hash_make(opt->pool);

    apr_xml_elem *group_elem = NULL;
    for (group_elem = ipgroup->first_child; group_elem; group_elem = group_elem->next) {
        if (!strcasecmp(group_elem->name, "group")) {
            apr_xml_attr *xml_attr = NULL;
            sipdump_ipgroup_item_t *item = NULL;
            for (xml_attr = group_elem->attr; xml_attr; xml_attr = xml_attr->next) {
                if (!strcasecmp(xml_attr->name, "name") && xml_attr->value) {
                    item = apr_pcalloc(opt->pool, sizeof(sipdump_ipgroup_item_t));
                    item->name = apr_pstrdup(opt->pool, xml_attr->value);
                    item->ips = apr_pcalloc(opt->pool, sizeof(uint32_t)  *IPGROUP_MAX_IP);
                    item->count = 0;
                    break;
                }
            }

            if (item) {
                apr_xml_elem *ip_elem = NULL;
                for (ip_elem = group_elem->first_child; ip_elem; ip_elem = ip_elem->next) {
                    if (!APR_XML_ELEM_IS_EMPTY(ip_elem)) {
                        item->ips[item->count] = sipdump_network_pton(ip_elem->first_cdata.first->text);
                        SIPDUMP_LOG(SIPDUMP_PRIO_INFO, "OPT ip_group: %s -> 0x%08X", item->name, item->ips[item->count]);
                        item->count++; 
                        if (item->count >= IPGROUP_MAX_IP) {
                            break;
                        }
                    }
                }

                apr_hash_set(hash, item->name, APR_HASH_KEY_STRING, item);
            }
        }
    }

    opt->ipgroup.hash = hash;

    return APR_SUCCESS;
}


static apr_status_t sipdump_opt_config_plugin_load(sipdump_opt_t *opt, apr_xml_elem *plugin) {
    assert(opt);
    assert(plugin);

    apr_xml_attr *xml_attr = NULL;
    for (xml_attr = plugin->attr; xml_attr; xml_attr = xml_attr->next) {
        if (!strcasecmp(xml_attr->name, "dir")) {
            sipdump_plugins_module_dir_set(xml_attr->value);
        }
    }

    apr_xml_elem *module_elem = NULL;
    for (module_elem = plugin->first_child; module_elem; module_elem = module_elem->next) {
        if (!strcasecmp(module_elem->name, "module")) {
            apr_xml_attr *xml_attr = NULL;
            const char *id = NULL;
            const char *name = NULL;
            apr_uint32_t enable = FALSE;
            for (xml_attr = module_elem->attr; xml_attr; xml_attr = xml_attr->next) {
                if (!strcasecmp(xml_attr->name, "id")) {
                    id = xml_attr->value;
                } else if (!strcasecmp(xml_attr->name, "name")) {
                    name = xml_attr->value;
                } else if (!strcasecmp(xml_attr->name, "enable")) {
                    enable = !strcasecmp(xml_attr->value, "true");
                }
            }

            if (id && name) {
                sipdump_plugins_module_add(id, name, enable);
            }
        }
    }


    return APR_SUCCESS;
}

apr_status_t sipdump_opt_config_load(sipdump_opt_t *opt, const char *path) {
    assert(opt);
    assert(path);

    opt->cfg_path = apr_pstrdup(opt->pool, path);
    apr_file_t *cfg_file = NULL;
    apr_status_t rv = apr_file_open(&cfg_file, opt->cfg_path, APR_FOPEN_READ | APR_FOPEN_BINARY, APR_FPROT_OS_DEFAULT, opt->pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_xml_parser *parser = NULL;
    apr_xml_doc *doc = NULL;
    rv = apr_xml_parse_file(opt->pool, &parser, &doc, cfg_file, 2000);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_xml_elem *root = doc->root;
    if (!root || strcasecmp(root->name, "sipdump") != 0) {
        return APR_EINVAL;
    }

    apr_xml_elem *elem = NULL;
    for (elem = root->first_child; elem; elem = elem->next) {
        if (!strcasecmp(elem->name, "log-name")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_log_name_set(opt, elem->first_cdata.first->text);
            }
        } else if (!strcasecmp(elem->name, "log-mode")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_log_mode_set(opt, elem->first_cdata.first->text);
            }
        } else if (!strcasecmp(elem->name, "log-facility")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_log_facility_set(opt, elem->first_cdata.first->text);
            }
        } else if (!strcasecmp(elem->name, "interface")) {
            apr_xml_attr *xml_attr = NULL;
            for (xml_attr = elem->attr; xml_attr; xml_attr = xml_attr->next) {
                if (!strcasecmp(xml_attr->name, "type")) {
                    if (!strcasecmp(xml_attr->value, "eth")) {
                        if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                            sipdump_opt_eth_name_set(opt, elem->first_cdata.first->text);
                        }
                    } else if (!strcasecmp(xml_attr->value, "file")) {
                        if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                            sipdump_opt_pcap_name_set(opt, elem->first_cdata.first->text);
                        }
                    }
                }
            }
        } else if (!strcasecmp(elem->name, "pid")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_pid_file_set(opt, elem->first_cdata.first->text);
            }
        } else if (!strcasecmp(elem->name, "promiscuous")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_promisc_set(opt, !strcasecmp(elem->first_cdata.first->text, "true"));
            }
        } else if (!strcasecmp(elem->name, "record")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_pcap_record_path_set(opt, elem->first_cdata.first->text);
            }
        } else if (!strcasecmp(elem->name, "log-level")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_log_priority_set(opt, elem->first_cdata.first->text);
            }
        } else if (!strcasecmp(elem->name, "rtp-filter")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_rtp_filter_set(opt, elem->first_cdata.first->text);
            }
        } else if (!strcasecmp(elem->name, "limit-time")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_limit_time_set(opt, (apr_int32_t)apr_atoi64(elem->first_cdata.first->text));
            }
        } else if (!strcasecmp(elem->name, "pcap-filter-exp")) {
            if (!APR_XML_ELEM_IS_EMPTY(elem)) {
                sipdump_opt_pcap_filter_set(opt, elem->first_cdata.first->text);
            }
        } else if (!strcasecmp(elem->name, "ip-group")) {
            sipdump_opt_config_ipgroup_load(opt, elem);
        } else if (!strcasecmp(elem->name, "plugins")) {
            sipdump_opt_config_plugin_load(opt, elem);
        }
    }

    return rv;
}


apr_status_t sipdump_opt_log_name_set(sipdump_opt_t *opt, const char *name) {
    assert(opt);
    opt->log_name = apr_pstrdup(opt->pool, name);
    return APR_SUCCESS;
}

const char *sipdump_opt_log_name_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->log_name;
}

apr_status_t sipdump_opt_log_mode_set(sipdump_opt_t *opt, const char *mode) {
    assert(opt);
    opt->log_mode = apr_pstrdup(opt->pool, mode);
    return APR_SUCCESS;
}

const char *sipdump_opt_log_mode_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->log_mode;
}

apr_status_t sipdump_opt_log_facility_set(sipdump_opt_t *opt, const char *facility) {
    assert(opt);
#ifdef SIPDUMP_USE_SYS_LOG
    if (!strcmp(facility, "LOG_LOCAL0")) {
        opt->log_facility = (void*)LOG_LOCAL0;
    } else if (!strcmp(facility, "LOG_LOCAL1")) {
        opt->log_facility = (void*)LOG_LOCAL1;
    } else if (!strcmp(facility, "LOG_LOCAL2")) {
        opt->log_facility = (void*)LOG_LOCAL2;
    } else if (!strcmp(facility, "LOG_LOCAL3")) {
        opt->log_facility = (void*)LOG_LOCAL3;
    } else if (!strcmp(facility, "LOG_LOCAL4")) {
        opt->log_facility = (void*)LOG_LOCAL4;
    } else if (!strcmp(facility, "LOG_LOCAL5")) {
        opt->log_facility = (void*)LOG_LOCAL5;
    } else if (!strcmp(facility, "LOG_LOCAL6")) {
        opt->log_facility = (void*)LOG_LOCAL6;
    } else if (!strcmp(facility, "LOG_LOCAL7")) {
        opt->log_facility = (void*)LOG_LOCAL7;
    }
#else
    if (!strcmp(facility, "stdout")) {
        opt->log_facility = (void*)stdout;
    } else if (!strcmp(facility, "stderr")) {
        opt->log_facility = (void*)stderr;
    }
#endif
    return APR_SUCCESS;
}

void* sipdump_opt_log_facility_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->log_facility;
}

apr_status_t sipdump_opt_log_priority_set(sipdump_opt_t *opt, const char *priority) {
    assert(opt);
    assert(priority);
    opt->log_priority = sipdump_log_priority_set(priority);
    return APR_SUCCESS;
}

int sipdump_opt_log_priority_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->log_priority;
}

apr_status_t sipdump_opt_eth_name_set(sipdump_opt_t *opt, const char *name) {
    assert(opt);

    if (SIPDUMP_ZSTR(name)) {
        return APR_BADARG;
    }

    opt->eth_name = apr_pstrdup(opt->pool, name);
    opt->pcap_name = NULL;
    return APR_SUCCESS;
}

const char *sipdump_opt_eth_name_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->eth_name;
}

apr_status_t sipdump_opt_pcap_name_set(sipdump_opt_t *opt, const char *name) {
    assert(opt);

    if (SIPDUMP_ZSTR(name)) {
        return APR_BADARG;
    }

    opt->pcap_name = apr_pstrdup(opt->pool, name);
    opt->eth_name = NULL;
    return APR_SUCCESS;
}

const char *sipdump_opt_pcap_name_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->pcap_name;
}

apr_status_t sipdump_opt_pcap_filter_set(sipdump_opt_t *opt, const char *filter) {
    assert(opt);
    if (SIPDUMP_ZSTR(filter)) {
        return APR_BADARG;
    }
    opt->pcap_filter = apr_pstrdup(opt->pool, filter);
    return APR_SUCCESS;
}

const char *sipdump_opt_pcap_filter_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->pcap_filter;
}

apr_status_t sipdump_opt_sip_method_filter_set(sipdump_opt_t *opt, const char *filter) {
    assert(opt);

    sipdump_sip_method_filter_t *sip_method_filter = &opt->sip_method_filter;

    if (SIPDUMP_ZSTR(filter)) {
        sip_method_filter->used = 0;
        sip_method_filter->num = 0;
        sip_method_filter->org_str.str = NULL;
        sip_method_filter->org_str.len = 0;
        return APR_SUCCESS;
    }

    char *dump_str = apr_pstrdup(opt->pool, filter);
    sip_method_filter->org_str.str = apr_pstrdup(opt->pool, filter);
    sip_method_filter->org_str.len = strlen(sip_method_filter->org_str.str);
    char *tmp = NULL;
    char *p = apr_strtok(dump_str, ",;|", &tmp);
    sip_method_filter->used = TRUE;
    sip_method_filter->num = 0;
    while (p && sip_method_filter->num < METHOD_FILTER_MAX) {
        sipdump_sip_method_get(p, -1, &sip_method_filter->methods[sip_method_filter->num], NULL);
        sip_method_filter->num++;
        p = apr_strtok(NULL, ",;|", &tmp);
    }
    return APR_SUCCESS;
}

int sipdump_opt_sip_method_filter_test(sipdump_opt_t *opt, int method) {
    assert(opt);

    sipdump_sip_method_filter_t *sip_method_filter = &opt->sip_method_filter;
    if (!sip_method_filter->used) {
        SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "OPT SIP filter is not used"); 
        return TRUE;
    }

    int i = 0;
    for (i = 0 ; i < sip_method_filter->num ; i++) {
        if (sip_method_filter->methods[i] == method) {
            SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "OPT SIP filter matched on %d", i); 
            return TRUE;
        }
    }

    return FALSE;
}

apr_status_t sipdump_opt_number_filter_set(sipdump_opt_t *opt, const char *filter) {
    assert(opt);

    sipdump_number_filter_t *number_filter = &opt->number_filter;

    if (number_filter->used) {
        regfree(&number_filter->regex);
    }

    if (SIPDUMP_ZSTR(filter)) {
        number_filter->used = 0;
        number_filter->org_str.str = NULL;
        number_filter->org_str.len = 0;
        return APR_SUCCESS;
    }

    number_filter->used = TRUE;
    number_filter->org_str.str = apr_pstrdup(opt->pool, filter);
    number_filter->org_str.len = strlen(number_filter->org_str.str);
    regcomp(&number_filter->regex, number_filter->org_str.str, REG_EXTENDED);

    return APR_SUCCESS;
}

apr_status_t sipdump_opt_pcap_record_path_set(sipdump_opt_t *opt, const char *path) {
    assert(opt);

    if (SIPDUMP_ZSTR(path)) {
        return APR_BADARG;
    }

    opt->record_path = apr_pstrdup(opt->pool, path);
    return APR_SUCCESS;
}

const char *sipdump_opt_pcap_record_path_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->record_path;
}

int sipdump_opt_number_filter_test(sipdump_opt_t *opt, const char *number) {
    assert(opt);

    sipdump_number_filter_t *number_filter = &opt->number_filter;
    if (!number_filter->used) {
        return TRUE;
    }

    if (SIPDUMP_ZSTR(number)) {
        return TRUE;
    }

    regmatch_t match[1];
    return regexec(&number_filter->regex, number, sizeof(match), match, 0) == REG_NOERROR;
}


apr_status_t sipdump_opt_promisc_set(sipdump_opt_t *opt, int promisc) {
    assert(opt);
    opt->pcap_promisc = !!promisc;
    return APR_SUCCESS;
}

int sipdump_opt_promisc_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->pcap_promisc;
}

apr_status_t sipdump_opt_rtp_filter_set(sipdump_opt_t *opt, const char *filter) {
    assert(opt);
    if (SIPDUMP_ZSTR(filter)) {
        return APR_SUCCESS;
    }
    sipdump_sip_rtp_filter_t *rtp_filter = &opt->rtp_filter;
    int types = SIPDUMP_RTP_CAPTURE_UNKNOWN;
    char *dump_str = apr_pstrdup(opt->pool, filter);
    rtp_filter->org_str.str = apr_pstrdup(opt->pool, filter);
    rtp_filter->org_str.len = strlen(rtp_filter->org_str.str);

    if (!strcasecmp(filter, "all")) {
        types = SIPDUMP_RTP_CAPTURE_ALL;
    } else {
        char *tmp = NULL;
        char *p = apr_strtok(dump_str, ",;|", &tmp);
        while (p) {
            if (!strncasecmp(p, "rtp", sizeof("rtp") - 1)) {
                types |= SIPDUMP_RTP_CAPTURE_RTP;
            } else if (!strncasecmp(p, "rtcp", sizeof("rtcp") - 1)) {
                types |= SIPDUMP_RTP_CAPTURE_RTCP;
            } else if (!strncasecmp(p, "event", sizeof("event") - 1)) {
                types |= SIPDUMP_RTP_CAPTURE_RTP_EVENT;
            }
            p = apr_strtok(NULL, ",;|", &tmp);
        }
    }
    rtp_filter->types = types;
    return APR_SUCCESS;
}

int sipdump_opt_rtp_filter_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->rtp_filter.types;
}

int sipdump_opt_rtp_filter_test(sipdump_opt_t *opt, int test) {
    assert(opt);
    return opt->rtp_filter.types & test;
}

apr_status_t sipdump_opt_pcap_buffer_size_set(sipdump_opt_t *opt, int pcap_buffer_size) {
    assert(opt);
    if (pcap_buffer_size < 0) {
        return APR_BADARG;
    }
    opt->pcap_buffer_size = pcap_buffer_size;
    return APR_SUCCESS;
}

int sipdump_opt_pcap_buffer_size_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->pcap_buffer_size;
}

apr_status_t sipdump_opt_pcap_flush_set(sipdump_opt_t *opt, int pcap_flush) {
    assert(opt);
    opt->pcap_flush = !!pcap_flush;
    return APR_SUCCESS;
}

int sipdump_opt_pcap_flush_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->pcap_flush;
}

apr_status_t sipdump_opt_limit_time_set(sipdump_opt_t *opt, apr_int64_t timeout) {
    assert(opt);
    opt->limit_time = timeout;
    return APR_SUCCESS;
}

apr_int64_t sipdump_opt_limit_time_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->limit_time;
}


apr_status_t sipdump_opt_pid_file_set(sipdump_opt_t *opt, const char *pid_file) {
    assert(opt);

    if (SIPDUMP_ZSTR(pid_file)) {
        return APR_BADARG;
    }

    opt->pid_file = apr_pstrdup(opt->pool, pid_file);
    return APR_SUCCESS;
}

const char *sipdump_opt_pid_file_get(sipdump_opt_t *opt) {
    assert(opt);
    return opt->pid_file;
}

apr_status_t sipdump_opt_ipgroup_get(sipdump_opt_t *opt, uint32_t ip, const sipdump_ipgroup_item_t **ipgroup) {
    assert(opt);
    assert(ipgroup);

    if (!opt->ipgroup.hash) {
        return APR_NOTFOUND;
    }

    apr_hash_index_t *hi;
    uint32_t found = FALSE;

    for (hi = apr_hash_first(NULL, opt->ipgroup.hash); hi; hi = apr_hash_next(hi)) {
        sipdump_ipgroup_item_t *item = NULL;
        apr_hash_this(hi, NULL, NULL, (void**)&item);
        if (item) {
            int i = 0;
            for (i = 0; i < item->count; i++) {
                if (item->ips[i] == ip) {
                    *ipgroup = item;
                    found = TRUE;
                    break;
                }
            }
            if (found) {
                break;
            }
        }
    }

    return found ? APR_SUCCESS : APR_NOTFOUND;
}