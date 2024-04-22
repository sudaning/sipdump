#include <stdio.h>

#include "sipdump_opt.h"
#include "sipdump_fragment.h"
#include "sipdump_session.h"

#include "test_sipdump_sip_hdr.h"
#include "test_sipdump_util.h"

int main(int argc, char *argv[]) {

    apr_initialize();
    sipdump_fragment_init();
    sipdump_session_init();

    sipdump_opt_t *opt = NULL;
    apr_status_t status = sipdump_opt_create(&opt);
    if (status != APR_SUCCESS) {
        printf("opt create error, status: %d\n", status);
        return 1;
    }

    status = sipdump_opt_cmd_parse(opt, argc, argv);
    if (status != APR_SUCCESS) {
        printf("%s", sipdump_opt_cmd_usage(argv[0]));
        return 1;
    }

    test_sipdump_sip_hdr_parse();
    test_sipdump_network_pton();
    return 0;
}