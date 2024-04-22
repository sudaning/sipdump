#ifndef SIPDUMP_SDP_H__
#define SIPDUMP_SDP_H__

#include <apr.h>

APR_BEGIN_DECLS

#include "sipdump_network.h"

#define SDP_START_FALG (TEXT_TOKEN_CRLF "" TEXT_TOKEN_CRLF)

#ifdef SIPDUMP_MRCP
struct sipdump_sdp_mrcp_t {
    struct network_addr media; /** 媒体信息 */
    sipdump_string_t channel_id; /** channel-identify信息 */
};
/** SDP中MRCP的信息 */
typedef struct sipdump_sdp_mrcp_t sipdump_sdp_mrcp_t;
#endif

struct sipdump_sdp_t {
    int has; /** 是否存在 */
    uint16_t checksum; /** 校验和 */
    struct network_addr audio_rtp; /** 音频RTP地址 */
    struct network_addr audio_rtcp; /** 音频RTCP地址 */
    struct network_addr video_rtp; /** 视频RTP地址 */
    struct network_addr video_rtcp; /** 视频RTCP地址 */
#ifdef SIPDUMP_MRCP
    sipdump_sdp_mrcp_t mrcp; /** MRCP信息 */
#endif
};
/** SIP的SDP信息 */
typedef struct sipdump_sdp_t sipdump_sdp_t;

/*!
  \brief 解析SDP
  \param data 数据指针
  \param size 数据大小
  \param pool 内存池
  \param sdp sdp
  \param content_length sdp长度
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_sdp_parse(const char *data, apr_size_t size, apr_pool_t *pool, sipdump_sdp_t *sdp, unsigned int content_length);

APR_END_DECLS

#endif