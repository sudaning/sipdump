#ifndef SIPDUMP_FRAGMENT_H__
#define SIPDUMP_FRAGMENT_H__

#include <apr.h>

APR_BEGIN_DECLS

#include "sipdump_network.h"

/*!
  \brief 初始化分片管理模块
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_fragment_init();

/*!
  \brief 反初始化分片管理模块
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_fragment_uninit();

/*!
  \brief 缓存分片数据
  \param pkt 数据包
  \return APR_ENOTENOUGHENTROPY：数据不够
        APR_SUCCESS：组包成功
        其他：错误码
*/
apr_status_t sipdump_fragment_cache(network_pkt_t *pkt);

APR_END_DECLS

#endif