
#ifndef SIPDUMP_UTIL_H__
#define SIPDUMP_UTIL_H__

#include <stdio.h>

#include <apr.h>
#include <apr_pools.h>

APR_BEGIN_DECLS

#define SIPDUMP_EXEC_NAME "sipdump"
#define SIPDUMP_PID_FILE "/var/run/sipdump.pid"
#define SIPDUMP_RECORD_PATH "./pcap/${year}-${month}-${day}/${hour}/${hour}${minute}${second}_${sip_call_id}.pcap"

struct sipdump_string_t {
    char *str; /** 字符指针 */
    apr_size_t len; /** 长度 */
};
/** 字符串定义 */
typedef struct sipdump_string_t sipdump_string_t;

long long sipdump_size_string_parse(char *s);
int sipdump_timestamp_snprintf(apr_time_t timestamp, char *buffer, apr_size_t size);
int sipdump_mkdir(const char *path, mode_t mode);
char *sipdump_network_ntop(uint8_t version, uint32_t ip, char *buffer, apr_size_t size);
uint32_t sipdump_network_pton(const char *src);
apr_size_t sipdump_separate_string(char *buf, char delim, char **array, apr_size_t arraylen);
#define sipdump_arraylen(_a) (sizeof(_a) / sizeof(_a[0]))
#define sipdump_split(_data, _delim, _array) sipdump_separate_string(_data, _delim, _array, sipdump_arraylen(_array))
char *sipdump_replace_string(const char *org, const char *rep, const char *to, apr_pool_t* pool);

// #define SIPDUMP_LOG(s, ...) 
#define SIPDUMP_ZSTR(s) (!s || s[0] == '\0')
#define SIPDUMP_YESNO(test) (test ? "yes" : "no")

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

APR_END_DECLS

#endif