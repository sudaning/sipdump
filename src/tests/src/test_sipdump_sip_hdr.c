#include <stdio.h>
#include "sipdump_sip_hdr.h"

int test_sipdump_sip_hdr_parse() {

    const char *data = "" \
        "INVITE sip:mresources@136.5.173.22:5060 SIP/2.0\r\n" \
        "via: SIP/2.0/TCP 136.6.226.9:63819;branch=z9hg4bk0a1790442133\r\n" \
        "Max-Forwards: 6\r\n"\
        "To: <tel:+02310000>\r\n" \
        "From: \"susu\"<sip:19122659976@136.6.226.9:5060>;tag=1790442133214522\r\n" \
        "Contact: <Sip:136.6.226.9:63819;transport=tcp>\r\n" \
        "Call-ID: 1790442133F2145@136.6.226.9\r\n" \
        "CSeq: 32332 INVITE\r\n" \
        "Content-Type: application/sdp\r\n" \
        "Content-Length: 305\r\n" \
        "\r\n" \
        "v=0\r\n" \
        "o=- 33580 337654 IN IP4 136.6.226.\r\n" \
        "s=ZTE MrcpClientLib\r\n" \
        "c=IN IP4 136.6.226.9\r\n" \
        "t=0 0\r\n" \
        "m=application 9 TCP/MRCPv2\r\n" \
        "a=setup:active\r\n" \
        "a=connection:new\r\n" \
        "a=resource:speechrecog\r\n" \
        "a=cmid:1\r\n" \
        "m=audio 27000 RTP/AVP 0 96\r\n" \
        "a=ptime:20\r\n" \
        "a=rtpmap:0 pcmu/8000\r\n" \
        "a=rtpmap:96 telephone-event/8000\r\n" \
        "a=sendonly\r\n" \
        "a=mid:1\r\n" \
        "";

    sipdump_sip_hdr_t hdr;
    int has_sdp = FALSE;
    memset(&hdr, 0, sizeof(sipdump_sip_hdr_t));
    apr_status_t rv = sipdump_sip_hdr_parse(data, strlen(data), &hdr, &has_sdp);
    printf("rv: %u\n", rv);
    printf("From\n");
    printf("display: %.*s(%d)\n", hdr.from.display.len, hdr.from.display.str, hdr.from.display.len);
    printf("scheme: %.*s(%d)\n", hdr.from.scheme.len, hdr.from.scheme.str, hdr.from.scheme.len);
    printf("user: %.*s(%d)\n", hdr.from.user.len, hdr.from.user.str, hdr.from.user.len);
    printf("host: %.*s(%d)\n", hdr.from.host.len, hdr.from.host.str, hdr.from.host.len);
    printf("port: %.*s(%d)\n", hdr.from.port.len, hdr.from.port.str, hdr.from.port.len);
    printf("params: %.*s(%d)\n", hdr.from.params.len, hdr.from.params.str, hdr.from.params.len);

    printf("To\n");
    printf("display: %.*s(%d)\n", hdr.to.display.len, hdr.to.display.str, hdr.to.display.len);
    printf("scheme: %.*s(%d)\n", hdr.to.scheme.len, hdr.to.scheme.str, hdr.to.scheme.len);
    printf("user: %.*s(%d)\n", hdr.to.user.len, hdr.to.user.str, hdr.to.user.len);
    printf("host: %.*s(%d)\n", hdr.to.host.len, hdr.to.host.str, hdr.to.host.len);
    printf("port: %.*s(%d)\n", hdr.to.port.len, hdr.to.port.str, hdr.to.port.len);
    printf("params: %.*s(%d)\n", hdr.to.params.len, hdr.to.params.str, hdr.to.params.len);

    return 0;
}