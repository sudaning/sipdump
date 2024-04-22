#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <arpa/inet.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_text.h"
#include "sipdump_sdp.h"

#define SDP_HDR_SKIP_BREAK(s) s += 1; TEXT_SPACES_SKIP(s); if (*s != TEXT_TOKEN_EQUAL) break; s++; TEXT_SPACES_SKIP(s)

static void sipdump_sdp_ip_parse(const char *data, apr_size_t size, uint32_t *ip) {
    const char *start = data;
    /** 'IN IP4 192.168.1.100' */
    data = strchr(data, TEXT_TOKEN_SP);
    if (!data) { return; }
    data += 1;
    /** ' IP4 192.168.1.100' */
    data = strchr(data, TEXT_TOKEN_SP);
    if (!data) { return; }
    data += 1;
    /** ' 192.168.1.100' */
    TEXT_SPACES_SKIP(data);
    /** '192.168.1.100' */
    int len = 0;
    SIPDUMP_TEXT_LINE_LEN_GET(data, start, size, len);
    char ip_addr[16] = {'\0'};
    strncpy(ip_addr, data, MIN(sizeof(ip_addr), len));
    inet_pton(AF_INET, ip_addr, ip);
    SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "SDP address: %s -> 0x%08X", ip_addr, *ip); 
    return;
}   

static uint16_t checksum(const char *packet, int packlen) {
	register unsigned long sum = 0;
    // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "SDP check sum len: %d", packlen); 

	while (packlen > 1) {
		sum += *(packet++);
		packlen -= 2;
	}

	if (packlen > 0)
		sum += *(unsigned char *)packet;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t) ~sum;
}

apr_status_t sipdump_sdp_parse(const char *data, apr_size_t size, apr_pool_t *pool, sipdump_sdp_t *sdp, unsigned int sip_hdr_content_length) {
    assert(data);
    assert(sdp);

    const char *tmp = data;
    const char *start = NULL;
    int line_index = 0;

    uint32_t ip = 0;
    struct network_addr *media_rtp = NULL;
    struct network_addr *media_rtcp = NULL;
    int rtcp_mux = FALSE;
#ifdef SIPDUMP_MRCP
    int has_mrcp = FALSE;
#endif
    /** 跳过SIP头域最后的字符 */
    start = strstr(tmp, SDP_START_FALG);
    if (!start) {
        return APR_BADARG;
    }
    start += sizeof(SDP_START_FALG) - 1;
    tmp = start;

    unsigned int r_content_length = size - (tmp - data);
    if (sip_hdr_content_length != r_content_length) {
        SIPDUMP_LOG(SIPDUMP_PRIO_WARNING, "SDP real len: %u is not equal sip header Content-Length: %u", 
            r_content_length, sip_hdr_content_length);
    }
    sdp->checksum = checksum(tmp, r_content_length);
    SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "SDP [%u] %.*s\n", r_content_length, r_content_length, tmp);
    /** 找到每一行的数据 */
    const char *line_start = tmp;
    do {
        char line_buffer[512] = {'\0'};
        const char *line = line_buffer;
        const char *line_end = strchr(line_start, TEXT_TOKEN_LF);
        int line_len = MIN(line_end + 1 - line_start, sizeof(line_buffer));
        if (line_end) {
            memcpy(line_buffer, line_start, line_len);
            line_index++;
        }
        // SIPDUMP_LOG(SIPDUMP_PRIO_TRACE, "SDP line [%u] (%u) %s", line_index, line_len, line);
        switch (*line) {
            case 'c': {
                /** 'c=IN IP4 192.168.1.100' */
                SDP_HDR_SKIP_BREAK(line);
                if (!media_rtp) {
                    sipdump_sdp_ip_parse(line, line_len, &ip);
                } else {
                    sipdump_sdp_ip_parse(line, line_len, &media_rtp->ip);
                    if (media_rtcp && !media_rtcp->ip) {
                        media_rtcp->ip = media_rtp->ip;
                    }
                }
                break;
            }

            case 'm': {
                SDP_HDR_SKIP_BREAK(line);
                media_rtp = NULL;
                if (!strncasecmp(line, "audio", sizeof("audio") - 1)) {
                    line += sizeof("audio") - 1;
                    media_rtp = &sdp->audio_rtp;
                    media_rtcp = &sdp->audio_rtcp;
                    rtcp_mux = FALSE;
                } else if (!strncasecmp(line, "video", sizeof("video") - 1)) {
                    line += sizeof("video") - 1;
                    media_rtp = &sdp->video_rtp;
                    media_rtcp = &sdp->video_rtcp;
                    rtcp_mux = FALSE;
#ifdef SIPDUMP_MRCP
                } else if (!strncasecmp(line, "application", sizeof("application") - 1)) {
                    line += sizeof("application") - 1;
                    if (strstr(line, "MRCP")) {
                        media_rtp = &sdp->mrcp.media;
                        has_mrcp = TRUE;
                    }
                    media_rtcp = NULL;
                    rtcp_mux = FALSE;
#endif
                }

                if (media_rtp) {
                    TEXT_SPACES_SKIP(line);
                    media_rtp->port = (uint16_t)apr_atoi64(line);
                    if (!media_rtp->ip) {
                        media_rtp->ip = ip;
                    }
                }

                if (media_rtcp) {
                    if (!media_rtcp->ip) {
                        media_rtcp->ip = ip;
                    }
                    if (rtcp_mux) {
                        media_rtcp->ip = media_rtp->ip;
                        media_rtcp->port = media_rtp->port;
                    }
                }
            }

            case 'a': {
                SDP_HDR_SKIP_BREAK(line);
                if (media_rtp) {
#ifdef SIPDUMP_MRCP
                    if (has_mrcp && !strncasecmp(line, "channel", sizeof("channel") - 1)) {
                        line += sizeof("channel") - 1;
                        TEXT_SPACES_SKIP(line);
                        if (*line == TEXT_TOKEN_COLON) {
                            line++;
                            TEXT_SPACES_SKIP(line);
                        }
                        sdp->mrcp.channel_id.str = apr_pstrdup(pool, line);
                        SIPDUMP_TEXT_LINE_LEN_GET(line, line, line_len, sdp->mrcp.channel_id.len);
                    }
#endif
                }

                if (media_rtcp) {
                    if (!strncasecmp(line, "rtcp:", sizeof("rtcp:") - 1)) {
                        line += sizeof("rtcp:") - 1;
                        TEXT_SPACES_SKIP(line);
                        media_rtcp->port = (uint16_t)apr_atoi64(line);
                        line = strchr(line, TEXT_TOKEN_SP);
                        if (line) {
                            TEXT_SPACES_SKIP(line);
                            uint32_t ip = 0;
                            sipdump_sdp_ip_parse(line, line_len, &ip);
                            if (!ip) {
                                media_rtcp->ip = ip;
                            }
                        }
                        
                    } else if (!strncasecmp(line, "rtcp-mux", sizeof("rtcp-mux") - 1)) {
                        if (!media_rtcp->ip || !media_rtcp->port) {
                            media_rtcp->ip = media_rtp->ip;
                            media_rtcp->port = media_rtp->port;
                        }
                        rtcp_mux = TRUE;
                    }
                }
                break;
            }
            default:
                break;
        }

        /** 开始下一行 */
        if (line_end) {
            line_start = line_end + 1;
        }

        /** 超出数据范围，退出 */
        if (line_start - start >= r_content_length || !line_end) {
            break;
        }

    } while(1);

    if (!sdp->audio_rtp.port) {
        sdp->audio_rtp.ip = 0;
        sdp->audio_rtcp.ip = 0;
    } else {
        if (!sdp->audio_rtcp.port) {
            sdp->audio_rtcp.port = sdp->audio_rtp.port ? (sdp->audio_rtp.port + 1) : 0;
        }

        if (!sdp->audio_rtcp.ip) {
            sdp->audio_rtcp.ip = ip;
        }
    }

    if (!sdp->video_rtp.port) {
        sdp->video_rtp.ip = 0;
        sdp->video_rtcp.ip = 0;
    } else {
        if (!sdp->video_rtcp.port) {
            sdp->video_rtcp.port = sdp->video_rtp.port ? (sdp->video_rtp.port + 1) : 0;
        }

        if (!sdp->video_rtcp.ip) {
            sdp->video_rtcp.ip = ip;
        }
    }
#ifdef SIPDUMP_MRCP
    if (!sdp->mrcp.media.port) {
        sdp->mrcp.media.ip = 0;
    } else {
        if (!sdp->mrcp.media.ip) {
            sdp->mrcp.media.ip = ip;
        }
    }
#endif

    return APR_SUCCESS;
}
