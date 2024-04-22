#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include "sipdump_util.h"

long long sipdump_size_string_parse(char *s) {
    char multiplier[32];
    long long result;
    int i;

    struct multiplier_element {
        char text[32];
        unsigned long value;
    } multipliers[] = {
        {"",1},
        {"b",1},
        {"kb",1024},
        {"mb",1024*1024},
        {"gb",1024*1024*1024},
        {"",0}
    };

    if (strlen(s)>=32){
        return 0;
    }
    result=0;
    multiplier[0]=0;
    sscanf (s,"%lld%s",&result,multiplier);
    for (i = 0; multipliers[i].value>0; i++){
        if (strcmp(multipliers[i].text,multiplier)==0){
            result*=multipliers[i].value;
            return result;
        }
    }
    return 0;
}

int sipdump_timestamp_snprintf(apr_time_t timestamp, char *buffer, apr_size_t size) {
    assert(buffer);

    if (timestamp) {
        apr_time_exp_t result;
        apr_time_exp_lt(&result, timestamp);
        return snprintf(buffer, size, "%4d-%02d-%02d %02d:%02d:%02d.%06d ",
            result.tm_year + 1900, result.tm_mon + 1, result.tm_mday,
            result.tm_hour, result.tm_min, result.tm_sec, result.tm_usec);
    }
    
    return snprintf(buffer, size, "(null)");
}

int sipdump_mkdir(const char *path, mode_t mode) {
    char s[256];
    char *p;
    struct stat sb;

    if (stat(path, &sb) == 0) {
        return 0;
    } else {
        strncpy(s, path, sizeof(s));
        p = strrchr(s, '/');
        if (p != NULL) {
            *p = '\0';
            if (sipdump_mkdir(s, mode) != 0) {
                return -1;
            }
        }
        return mkdir(path, mode);
    }
    return -1;
}

char *sipdump_network_ntop(uint8_t version, uint32_t ip, char *buffer, apr_size_t size) {

#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint32_t ip1 = (ip & 0x000000FF);
    uint32_t ip2 = (ip & 0x0000FF00) >> 8;
    uint32_t ip3 = (ip & 0x00FF0000) >> 16;
    uint32_t ip4 = (ip & 0xFF000000) >> 24;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint32_t ip4 = (ip & 0x000000FF);
    uint32_t ip3 = (ip & 0x0000FF00) >> 8;
    uint32_t ip2 = (ip & 0x00FF0000) >> 16;
    uint32_t ip1 = (ip & 0xFF000000) >> 24;
#else
# error	"Please fix <bits/endian.h>"
#endif
    
    snprintf(buffer, size, "%u.%u.%u.%u", ip1, ip2, ip3, ip4);
    return buffer;
}

unsigned int sipdump_network_pton(const char *src) {
    uint32_t ip = 0;
    uint8_t tmp[4] = {0};
    uint32_t cnt = 0;
    const char *tp = src;
    uint8_t digit = 0;

    while (*tp) {
        uint8_t ch = (uint8_t)*tp;
        tp++;
        if ('0' <= ch && ch <= '9') {
            digit = digit  *10 + (ch - '0');
        } else if (ch == '.') {
            tmp[cnt++] = digit;
            digit = 0;
            if (cnt >= sizeof(tmp)) {
                break;
            }
            continue;
        } else {
            return ip;
        }
    }

    if (cnt > sizeof(tmp)) {
        return ip;
    }
    tmp[cnt] = digit;

#if __BYTE_ORDER == __LITTLE_ENDIAN
    ip = (tmp[3] << 24) | (tmp[2] << 16) | (tmp[1] << 8) | tmp[0];
#elif __BYTE_ORDER == __BIG_ENDIAN
    ip = (tmp[0] << 24) | (tmp[1] << 16) | (tmp[2] << 8) | tmp[3];
#else
# error	"Please fix <bits/endian.h>"
#endif

    return ip;
}



#define ESCAPE_META '\\'

static char unescape_char(char escaped) {
    char unescaped;

    switch (escaped) {
    case 'n':
        unescaped = '\n';
        break;
    case 'r':
        unescaped = '\r';
        break;
    case 't':
        unescaped = '\t';
        break;
    case 's':
        unescaped = ' ';
        break;
    default:
        unescaped = escaped;
    }
    return unescaped;
}

static char *cleanup_separated_string(char *str, char delim) {
    char *ptr;
    char *dest;
    char *start;
    char *end = NULL;
    int inside_quotes = 0;

    /* Skip initial whitespace */
    for (ptr = str; *ptr == ' '; ++ptr) {
    }

    for (start = dest = ptr; *ptr; ++ptr) {
        char e;
        int esc = 0;

        if (*ptr == ESCAPE_META) {
            e = *(ptr + 1);
            if (e == '\'' || e == '"' || (delim && e == delim) || e == ESCAPE_META || (e = unescape_char(*(ptr + 1))) != *(ptr + 1)) {
                ++ptr;
                *dest++ = e;
                end = dest;
                esc++;
            }
        }
        if (!esc) {
            if (*ptr == '\'' && (inside_quotes || strchr(ptr+1, '\''))) {
                if ((inside_quotes = (1 - inside_quotes))) {
                    end = dest;
                }
            } else {
                *dest++ = *ptr;
                if (*ptr != ' ' || inside_quotes) {
                    end = dest;
                }
            }
        }
    }
    if (end) {
        *end = '\0';
    }

    return start;
}

static unsigned int separate_string_char_delim(char *buf, char delim, char **array, unsigned int arraylen) {
    enum tokenizer_state {
        START,
        FIND_DELIM
    } state = START;

    unsigned int count = 0;
    char *ptr = buf;
    int inside_quotes = 0;
    unsigned int i;

    while (*ptr && count < arraylen) {
        switch (state) {
        case START:
            array[count++] = ptr;
            state = FIND_DELIM;
            break;

        case FIND_DELIM:
            /* escaped characters are copied verbatim to the destination string */
            if (*ptr == ESCAPE_META) {
                ++ptr;
            } else if (*ptr == '\'' && (inside_quotes || strchr(ptr+1, '\''))) {
                inside_quotes = (1 - inside_quotes);
            } else if (*ptr == delim && !inside_quotes) {
                *ptr = '\0';
                state = START;
            }
            ++ptr;
            break;
        }
    }
    /* strip quotes, escaped chars and leading / trailing spaces */

    for (i = 0; i < count; ++i) {
        array[i] = cleanup_separated_string(array[i], delim);
    }

    return count;
}

static unsigned int separate_string_blank_delim(char *buf, char **array, unsigned int arraylen) {
    enum tokenizer_state {
        START,
        SKIP_INITIAL_SPACE,
        FIND_DELIM,
        SKIP_ENDING_SPACE
    } state = START;

    unsigned int count = 0;
    char *ptr = buf;
    int inside_quotes = 0;
    unsigned int i;

    while (*ptr && count < arraylen) {
        switch (state) {
        case START:
            array[count++] = ptr;
            state = SKIP_INITIAL_SPACE;
            break;

        case SKIP_INITIAL_SPACE:
            if (*ptr == ' ') {
                ++ptr;
            } else {
                state = FIND_DELIM;
            }
            break;

        case FIND_DELIM:
            if (*ptr == ESCAPE_META) {
                ++ptr;
            } else if (*ptr == '\'') {
                inside_quotes = (1 - inside_quotes);
            } else if (*ptr == ' ' && !inside_quotes) {
                *ptr = '\0';
                state = SKIP_ENDING_SPACE;
            }
            ++ptr;
            break;

        case SKIP_ENDING_SPACE:
            if (*ptr == ' ') {
                ++ptr;
            } else {
                state = START;
            }
            break;
        }
    }
    /* strip quotes, escaped chars and leading / trailing spaces */

    for (i = 0; i < count; ++i) {
        array[i] = cleanup_separated_string(array[i], 0);
    }

    return count;
}

apr_size_t sipdump_separate_string(char *buf, char delim, char **array, apr_size_t arraylen) {
    if (!buf || !array || !arraylen) {
        return 0;
    }

    if (*buf == '^' && *(buf+1) == '^') {
        char *p = buf + 2;

        if (*p && *(p+1)) {
            buf = p;
            delim = *buf++;
        }
    }

    memset(array, 0, arraylen * sizeof(*array));

    return (delim == ' ' ? separate_string_blank_delim(buf, array, arraylen) : separate_string_char_delim(buf, delim, array, arraylen));
}

char *sipdump_replace_string(const char *org, const char *rep, const char *to, apr_pool_t *pool) {
    assert(org);
    assert(rep);
    assert(to);

    char *start = strstr(org, rep);
    if (!start) {
        return apr_pstrdup(pool, org);
    }

    char *end = start + strlen(rep);
    char *new = apr_psprintf(pool, "%.*s%s%s", start - org, org, to, end);
    return sipdump_replace_string(new, rep, to, pool);
}