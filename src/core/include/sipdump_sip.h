#ifndef SIPDUMP_SIP_H__
#define SIPDUMP_SIP_H__

#include <apr.h>

APR_BEGIN_DECLS

#include "sipdump_opt.h"
#include "sipdump_sdp.h"
#include "sipdump_sip_hdr.h"

#define SIPDUMP_SIP_PKT_LEN_MIN 32

enum sipdump_sip_method_e {
    SIPDUMP_SIP_METHOD_UNKNOWN, /** Invalid method name */
    SIPDUMP_SIP_METHOD_INVITE, /** INVITE */
    SIPDUMP_SIP_METHOD_ACK, /** ACK */
    SIPDUMP_SIP_METHOD_CANCEL, /** CANCEL */
    SIPDUMP_SIP_METHOD_BYE, /** BYE */
    SIPDUMP_SIP_METHOD_OPTIONS, /** OPTIONS */
    SIPDUMP_SIP_METHOD_REGISTER, /** REGISTER */
    SIPDUMP_SIP_METHOD_INFO, /** INFO */
    SIPDUMP_SIP_METHOD_PRACK, /** PRACK */
    SIPDUMP_SIP_METHOD_UPDATE, /** UPDATE */
    SIPDUMP_SIP_METHOD_MESSAGE, /** MESSAGE */
    SIPDUMP_SIP_METHOD_SUBSCRIBE, /** SUBSCRIBE */
    SIPDUMP_SIP_METHOD_NOTIFY, /** NOTIFY */
    SIPDUMP_SIP_METHOD_REFER, /** REFER */
    SIPDUMP_SIP_METHOD_PUBLISH, /** PUBLISH */
};
/** SIP方法 */
typedef enum sipdump_sip_method_e sipdump_sip_method_e;

/** SIP响应码 */
typedef unsigned int sipdump_sip_code;

struct sipdump_sip_t {
    sipdump_sip_method_e method; /** 请求方法 */
    sipdump_sip_code code; /** 响应码 */
    sipdump_sip_hdr_t hdr; /** 头域 */
    sipdump_sdp_t sdp; /** SDP */
};
/** SIP信息 */
typedef struct sipdump_sip_t sipdump_sip_t;

apr_status_t sipdump_sip_init_opt(sipdump_opt_t* opt);
apr_status_t sipdump_sip_uninit();

apr_status_t sipdump_sip_hdr_pre_parse_add(char hdrs[][SIPDUMP_HEADER_NAME_MAX], apr_size_t count);

/*!
  \brief 解析SIP起始行
  \param data 数据
  \param size 大小
  \param method 请求方法
  \param method_name 请求方法名
  \param code 响应码
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_sip_start_line_get(const char *data, apr_size_t size, sipdump_sip_method_e *method, const char **method_name, sipdump_sip_code *code);

/*!
  \brief 解析SIP方法
  \param data 数据
  \param size 大小
  \param method 请求方法
  \param method_name 请求方法名
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_sip_method_get(const char *data, apr_size_t size, int *method, const char **method_name);

/*!
  \brief 解析SIP
  \param data 数据
  \param size 大小
  \param method 请求方法
  \param code 响应码
  \param sip SIP信息
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_sip_parse(const char *data, apr_size_t size, sipdump_sip_method_e method, sipdump_sip_code code, sipdump_sip_t *sip);

/*!
  \brief 获取SIP Call-ID
  \param sip SIP信息
  \return 成功返回Call-ID，失败返回NULL
*/
const sipdump_string_t *sipdump_sip_call_id_get(const sipdump_sip_t *sip);
const sipdump_sip_hdr_from_t *sipdump_sip_from_get(const sipdump_sip_t *sip);
const sipdump_sip_hdr_to_t *sipdump_sip_to_get(const sipdump_sip_t *sip);

/*!
  \brief 测试方法是否能创建会话
  \param method 方法
  \return 成功TRUE，失败FALSE
*/
int sipdump_sip_create_session_method_test(sipdump_sip_method_e method);

APR_END_DECLS

#endif