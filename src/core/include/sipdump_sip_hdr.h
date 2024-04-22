#ifndef SIPDUMP_SIP_HDR_H__
#define SIPDUMP_SIP_HDR_H__

#include <apr.h>

#include "sipdump_util.h"
#include "sipdump_text.h"

APR_BEGIN_DECLS

/** SIP头域（含简写）RFC出处一览表
Accept  RFC 3261
Accept-Contact  a      RFC 3841
Accept-Encoding  RFC 3261
Accept-Language  RFC 3261
Accept-Resource-Priority  RFC 4412
Alert-Info  RFC 3261
Allow  RFC 3261
Allow-Events    u  RFC 3265
Answer-Mode  RFC 5373
Authentication-Info  RFC 3261
Authorization  RFC 3261
Call-ID      i RFC 3261
Call-Info  RFC 3261
Contact  m      RFC 3261
Content-Disposition  RFC 3261
Content-Encoding e    RFC 3261
Content-Language  RFC 3261
Content-Length     l   RFC 3261
Content-Type          c    RFC 3261
CSeq  RFC 3261
Date  RFC 3261
Encryption  (deprecated) RFC 3261
Error-Info  RFC 3261
Event  o   RFC 3265
Expires  RFC 3261
Flow-Timer  RFC 5626
From          f RFC 3261
Hide  (deprecated) RFC 3261
History-Info  RFC 4244, RFC 6044
Identity  y RFC 4474
Identity-Info n           RFC 4474
In-Reply-To  RFC 3261
Join  RFC 3911
Max-Breadth  RFC 5393
Max-Forwards  RFC 3261
MIME-Version  RFC 3261
Min-Expires  RFC 3261
Min-SE  RFC 4028
Organization  RFC 3261
P-Access-Network-Info  RFC 3455
P-Answer-State  RFC 4964
P-Asserted-Identity  RFC 3325
P-Asserted-Service  RFC 6050
P-Associated-URI  RFC 3455
P-Called-Party-ID  RFC 3455
P-Charging-Function-Addresses  RFC 3455
P-Charging-Vector  RFC 3455
P-DCS-Billing-Info  RFC 5503
P-DCS-LAES  RFC 5503
P-DCS-OSPS  RFC 5503
P-DCS-Redirect  RFC 5503
P-DCS-Trace-Party-ID  RFC 3603
P-Early-Media  RFC 5009
P-Media-Authorization  RFC 3313
P-Preferred-Identity  RFC 3325
P-Preferred-Service  RFC 6050
P-Profile-Key  RFC 5002
P-Refused-URI-List  RFC 5318
P-Served-User  RFC 5502
P-User-Database  RFC 4457
P-Visited-Network-ID  RFC 3455
Path  RFC 3327
Permission-Missing  RFC 5360
Policy-Contact  
Policy-ID  
Priority  RFC 3261
Priv-Answer-Mode  RFC 5373
Privacy  RFC 3323
Proxy-Authenticate  RFC 3261
Proxy-Authorization  RFC 3261
Proxy-Require  RFC 3261
RAck  RFC 3262
Reason  RFC 3326
Record-Route  RFC 3261
Refer-Sub  RFC 4488
Referred-By  RFC 3892
Replaces  RFC 3891
Resource-Priority  RFC 4412
Response-Key  (deprecated) RFC 3261
Retry-After  RFC 3261
Route  RFC 3261
RSeq  RFC 3262
Security-Client  RFC 3329
Security-Server  RFC 3329
Security-Verify  RFC 3329
Server  RFC 3261
Service-Route  RFC 3608
Session-Expires x           RFC 4028
SIP-ETag  RFC 3903
SIP-If-Match  RFC 3903
Subject           s            RFC 3261
Subscription-State  RFC 3265
Supported          k RFC 3261
Suppress-If-Match  RFC 5839
Target-Dialog  RFC 4538
Timestamp  RFC 3261
To t             RFC 3261
Trigger-Consent  RFC 5360
Unsupported  RFC 3261
User-Agent  RFC 3261
Via           v              RFC 3261
Warning  RFC 3261
WWW-Authenticate  RFC 3261
*/

#define SIPDUMP_HEADER_NAME_MAX 32

struct sipdump_sip_hdr_cseq_t {
    unsigned int seq; /** 序号 */
    int method; /** 方法 */
    const char *method_name; /** 方法名 */
};
/** SIP CSeq头域 */
typedef struct sipdump_sip_hdr_cseq_t sipdump_sip_hdr_cseq_t;

struct sipdump_sip_hdr_addr_t {
    sipdump_string_t display; /** 显示名 */
    sipdump_string_t scheme; /** sip: sips: tel: */
    sipdump_string_t user;
    sipdump_string_t host;
    sipdump_string_t port;
    sipdump_string_t params;
};
/** SIP CSeq头域 */
typedef struct sipdump_sip_hdr_addr_t sipdump_sip_hdr_from_t;
typedef struct sipdump_sip_hdr_addr_t sipdump_sip_hdr_to_t;

struct sipdump_sip_hdr_common_t {
    sipdump_string_t name;
    sipdump_string_t value;
};
typedef struct sipdump_sip_hdr_common_t sipdump_sip_hdr_common_t;

#define SIPDUMP_HDR_EXT_MAX 64

struct sipdump_sip_hdr_t {
    sipdump_sip_hdr_from_t from; /** From */
    sipdump_sip_hdr_to_t to; /** To */
    sipdump_string_t call_id; /** Call-ID */
    unsigned int content_length; /** Content-Length */
    sipdump_string_t content_type; /** Content-Type */
    sipdump_sip_hdr_cseq_t cseq; /** CSeq */

    /** ext */
    sipdump_sip_hdr_common_t hdrs[SIPDUMP_HDR_EXT_MAX];
    apr_uint32_t count;
};
/** SIP头域 */
typedef struct sipdump_sip_hdr_t sipdump_sip_hdr_t;


#define SIP_HDR_BASE_S ""
#define SIP_HDR_VIA "Via"
#define SIP_HDR_VIA_S "v"
#define SIP_HDR_CALL_ID "Call-ID"
#define SIP_HDR_CALL_ID_S "i"
#define SIP_HDR_FROM "From"
#define SIP_HDR_FROM_S "f"
#define SIP_HDR_TO "To"
#define SIP_HDR_TO_S "t"
#define SIP_HDR_CSEQ "CSeq"
#define SIP_HDR_CONTENT_LEN "Content-Length"
#define SIP_HDR_CONTENT_LEN_S "l"
#define SIP_HDR_CONTENT_TYPE "Content-Type"
#define SIP_HDR_CONTENT_TYPE_S "c"

#define SIP_VALUE_APPLICATION_SDP "application/sdp"


/*!
  \brief 解析SIP头域
  \param data 数据
  \param size 大小
  \param hdr 头域
  \param has_sdp 是否存在SDP
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_sip_hdr_parse(const char *data, apr_size_t size, sipdump_text_field_t* hdr_fields, apr_uint32_t hdr_field_count, sipdump_sip_hdr_t *hdr);


APR_END_DECLS

#endif