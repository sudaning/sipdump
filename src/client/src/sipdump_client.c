#include <stdio.h>
#include <signal.h>

#include <apr_general.h>

#include "sipdump_util.h"
#include "sipdump_log.h"
#include "sipdump_opt.h"
#include "sipdump_pcap.h"
#include "sipdump_plugins.h"
#include "sipdump_fragment.h"
#include "sipdump_session.h"

static sipdump_pcap_t *pcap = NULL;

void sigint_handler(int param) {
    printf("\n");
    // printf("\nSIGINT received, terminating\n");
    if (pcap) {
        sipdump_pcap_stop(pcap);
    }
}

void sigterm_handler(int param) {
    printf("\n");
    // printf("\nSIGTERM received, terminating\n");
    if (pcap) {
        sipdump_pcap_stop(pcap);
    }
}

int main(int argc, char *argv[]) {
    int ret = 0;
    apr_status_t status;
    sipdump_opt_t *opt = NULL;

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigterm_handler);
    
    apr_initialize();
    sipdump_fragment_init();
    sipdump_session_init();
    sipdump_plugins_init();

    // printf("%s starting...\n", argv[0]);
    
    status = sipdump_opt_create(&opt);
    if (status != APR_SUCCESS) {
        printf("opt create error, status: %d\n", status);
        ret = 1;
        goto error;
    }

    status = sipdump_opt_cmd_parse(opt, argc, argv);
    if (status != APR_SUCCESS) {
        printf("%s", sipdump_opt_cmd_usage(argv[0]));
        ret = 2;
        goto error;
    }

    sipdump_log_init(sipdump_opt_log_name_get(opt), sipdump_opt_log_mode_get(opt), sipdump_opt_log_facility_get(opt));

    status = sipdump_pcap_create(&pcap);
    if (status != APR_SUCCESS) {
        printf("pcap create error, status: %d\n", status);
        ret = 3;
        goto error;
    }

    status = sipdump_pcap_init_opt(pcap, opt);
    if (status != APR_SUCCESS) {
        printf("pcap init opt error, status: %d\n", status);
        ret = 4;
        goto error;
    }

    status = sipdump_sip_init_opt(opt);
    if (status != APR_SUCCESS) {
        printf("pcap init opt error, status: %d\n", status);
        ret = 4;
        goto error;
    }

    status = sipdump_pcap_run(pcap);
    if (status != APR_SUCCESS) {
        printf("pcap run error, status: %d\n", status);
        ret = 5;
        goto error;
    }

    sipdump_pcap_wait_exit(pcap);

error:
    if (pcap) {
        sipdump_pcap_destroy(pcap);
        pcap = NULL;
    }

    if (opt) {
        sipdump_opt_destroy(opt);
        opt = NULL;
    }

    sipdump_session_uninit();
    sipdump_plugins_uninit();
    sipdump_fragment_uninit();
    apr_terminate();

    return ret;
}