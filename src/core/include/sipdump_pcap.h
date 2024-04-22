#ifndef SIPDUMP_PCAP_H__
#define SIPDUMP_PCAP_H__

#include <apr.h>

APR_BEGIN_DECLS

#include "sipdump_opt.h"

/** pcap对象 */
typedef struct sipdump_pcap_t sipdump_pcap_t;

/*!
  \brief 创建pcap对象
  \param pcap pcap对象
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_pcap_create(sipdump_pcap_t **pcap);

/*!
  \brief 销毁pcap对象
  \param pcap pcap对象
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_pcap_destroy(sipdump_pcap_t *pcap);

/*!
  \brief 初始化pcap对象
  \param pcap pcap对象
  \param opt 配置参数
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_pcap_init_opt(sipdump_pcap_t *pcap, sipdump_opt_t *opt);

/*!
  \brief 运行pcap
  \param pcap pcap对象
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_pcap_run(sipdump_pcap_t *pcap);

/*!
  \brief 停止pcap
  \param pcap pcap对象
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_pcap_stop(sipdump_pcap_t *pcap);

/*!
  \brief 等待pcap停止退出
  \param pcap pcap对象
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_pcap_wait_exit(sipdump_pcap_t *pcap);

APR_END_DECLS

#endif