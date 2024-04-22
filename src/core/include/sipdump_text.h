#ifndef SIPDUMP_TEXT_H__
#define SIPDUMP_TEXT_H__

#include <apr.h>
#include <apr_pools.h>
#include <apr_hash.h>

APR_BEGIN_DECLS

#define TEXT_TOKEN_SP ' ' /** 空格 */
#define TEXT_TOKEN_HTAB '\t' /** 制表符 */
#define TEXT_TOKEN_CR '\r' /** 回车 */
#define TEXT_TOKEN_LF '\n' /** 换行 */
#define TEXT_TOKEN_COLON ':' /** 冒号 */
#define TEXT_TOKEN_EQUAL '=' /** 等于 */
#define TEXT_TOKEN_CRLF "\r\n" /** 回车换行 */

/** 跳过空格 */
#define TEXT_SPACES_SKIP(s) while(*s == TEXT_TOKEN_SP) { s++; }

struct sipdump_text_field_t {
    sipdump_string_t hdr; /** 头域 */
    sipdump_string_t shdr; /** 简写头域 */
    sipdump_string_t val; /** 值 */
    int match; /** 是否存在（匹配） */
};
/** 文本域 */
typedef struct sipdump_text_field_t sipdump_text_field_t;

/** 初始化文本域 */
#define SIPDUMP_TEXT_HDR_ITEM_INIT(hdr_name, shdr_name) { {hdr_name, sizeof(hdr_name) - 1}, {shdr_name, sizeof(shdr_name) - 1}, {NULL, 0}, FALSE }

/** 获取文本行末长度 */
#define SIPDUMP_TEXT_LINE_LEN_GET(tmp, data_org_start, data_size, len) \
    do { \
        const char *endline = strchr(tmp, TEXT_TOKEN_LF); \
        if (!endline) { \
            endline = strchr(tmp, TEXT_TOKEN_CR); \
        } \
        if (endline && endline - data_org_start <= data_size) { \
            /** 跳过\n */\
            endline -= 1; \
            /** 跳过\r */ \
            if (*endline == TEXT_TOKEN_CR || *endline == TEXT_TOKEN_LF) { \
                endline -= 1; \
            } \
            len = endline - tmp + 1; \
        } else { \
            len = 0; \
        } \
    }while(0)

/*!
  \brief 解析文本域
  \param data 数据
  \param size 大小
  \param sp 分隔符
  \param fields 需要解析的域
  \param field_size 域大小
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_text_parse(const char *data, apr_size_t size, char sp, sipdump_text_field_t *fields, apr_size_t field_size);

apr_status_t sipdump_text_complete_parse(const char *data, apr_size_t size, apr_pool_t *pool, apr_hash_t *hdr, char **body, apr_size_t *body_size);

APR_END_DECLS

#endif