#ifndef SIPDUMP_SESSION_H__
#define SIPDUMP_SESSION_H__

#include <apr.h>
#include <pcap.h>

APR_BEGIN_DECLS

#include "sipdump_sip.h"
#include "sipdump_network.h"
#ifdef SIPDUMP_MRCP
#include "sipdump_mrcp.h"
#endif
/** 会话句柄 */
typedef struct sipdump_session_t sipdump_session_t;

/*!
  \brief 初始化
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_init();

/*!
  \brief 反初始化
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_uninit();

/*!
  \brief 创建会话
  \param session 会话
  \param pkt 包
  \param opt 选项
  \param pcap_handle pcap句柄
  \param sip sip消息
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_create(sipdump_session_t **session, network_pkt_t *pkt, sipdump_opt_t *opt, pcap_t *pcap_handle, sipdump_sip_t *sip);

/*!
  \brief 销毁会话
  \param session 会话
  \param pkt 包
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_destroy(sipdump_session_t *session, network_pkt_t *pkt);

/*!
  \brief 结束会话
  \param session 会话
  \param pkt 包
  \param destroy 是否销毁
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_terminating(sipdump_session_t *session, network_pkt_t *pkt, int destroy);

/*!
  \brief 清除无效会话
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_zombie_kill(network_pkt_t *pkt);

/*!
  \brief 获取内存池
  \return 成功返回内存池对象，失败返回NULL
*/
apr_pool_t *sipdump_session_pool_get(sipdump_session_t *session);

/*!
  \brief 保存插件用户数据
  \return 成功返回内存池对象，失败返回NULL
*/
void sipdump_session_plugin_user_data_set(sipdump_session_t *session, void* user_data);

/*!
  \brief 获取插件用户数据
  \return 成功返回数据指针，失败返回NULL
*/
void *sipdump_session_plugin_user_data_get(sipdump_session_t *session);


/*!
  \brief 获取uuid
  \param session 会话
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
const char *sipdump_session_uuid_get(sipdump_session_t *session);

/*!
  \brief 设置会话最后ack标记
  \param session 会话
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_last_ack_wait_set(sipdump_session_t *session);

/*!
  \brief 获取会话最后ack标记
  \param session 会话
  \return ack标记
*/
int sipdump_session_last_ack_wait_get(sipdump_session_t *session);

/*!
  \brief 获取会话收集包数量
  \param session 会话
  \param pkt_type 包种类
  \return 数量
*/
unsigned int sipdump_session_pcap_pkt_count_get(sipdump_session_t *session, network_pkt_type_e pkt_type);

/*!
  \brief 通过网络socket pair查找回话
  \param socket_pair 会话
  \param pkt_type 包类型
  \return 成功返回会话句柄，失败返回NULL
*/
sipdump_session_t *sipdump_session_pkt_find(const struct network_socket_pair *socket_pair, network_pkt_type_e *pkt_type);

/*!
  \brief 存储pcap数据到会话中
  \param session 会话
  \param pkt_header 头
  \param pkt_data 数据
  \param pkt_type 类型
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_pkt_save(sipdump_session_t *session, struct pcap_pkthdr *pkt_header, const u_char *pkt_data, network_pkt_type_e pkt_type);

/*!
  \brief 通过SIP Call-ID找会话
  \param call_id SIP Call-ID
  \return 成功返回会话句柄，失败返回NULL
*/
sipdump_session_t *sipdump_session_sip_find(const sipdump_string_t *call_id);

/*!
  \brief 添加SIP头域到会话中
  \param session 会话
  \param socket_pair SIP包socket
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_sip_padding(sipdump_session_t *session, const struct network_socket_pair *socket_pair);

/*!
  \brief 添加SDP到会话中
  \param session 会话
  \param sdp SDP
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_sip_sdp_padding(sipdump_session_t *session, const sipdump_sdp_t *sdp);

#ifdef SIPDUMP_MRCP
/*!
  \brief 通过MRCP Channel-Identity找会话
  \param channel_id MRCP Channel-Identity
  \return 成功返回会话句柄，失败返回NULL
*/
sipdump_session_t *sipdump_session_mrcp_find(const sipdump_string_t *channel_id);

/*!
  \brief 添加MRCP头域到会话中
  \param session 会话
  \param socket_pair MRCP包socket
  \param mrcp MRCP头域
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_session_mrcp_padding(sipdump_session_t *session, const struct network_socket_pair *socket_pair, const sipdump_mrcp_t *mrcp);
#endif

APR_END_DECLS

#endif