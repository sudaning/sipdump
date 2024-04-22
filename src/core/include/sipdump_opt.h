
#ifndef SIPDUMP_OPT_H__
#define SIPDUMP_OPT_H__

#include <apr.h>

APR_BEGIN_DECLS

#include "sipdump_util.h"

enum sipdump_rtp_capture_e {
    SIPDUMP_RTP_CAPTURE_NONE = 0, /** 不抓任何媒体包 */
    SIPDUMP_RTP_CAPTURE_RTP = 1 << 0, /** 抓RTP包 */
    SIPDUMP_RTP_CAPTURE_RTCP = 1 << 1, /** 抓RTCP包 */
    SIPDUMP_RTP_CAPTURE_RTP_EVENT = 1 << 2, /** 抓RTP EVENT包 */
    SIPDUMP_RTP_CAPTURE_UNKNOWN = 1 << 3, /** 无效值（必须比上一个有效值多左移一位） */
    SIPDUMP_RTP_CAPTURE_ALL = -1,
};
/** RTP抓包标记（任意组合） */
typedef enum sipdump_rtp_capture_e sipdump_rtp_capture_e;
/** 配置器 */
typedef struct sipdump_opt_t sipdump_opt_t;

#define IPGROUP_MAX_IP 4 /** IP组中ip最大数量 */

struct sipdump_ipgroup_item_t {
    const char *name;
    uint32_t *ips;
    uint32_t count;
};
typedef struct sipdump_ipgroup_item_t sipdump_ipgroup_item_t;

/*!
  \brief 创建配置选项
  \param opt 配置句柄
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_create(sipdump_opt_t **opt);

/*!
  \brief 销毁配置选项
  \param opt 配置句柄
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_destroy(sipdump_opt_t *opt);

/*!
  \brief 从命令行中解析配置
  \param opt 配置句柄
  \param argc 参数个数
  \param argv 参数
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_cmd_parse(sipdump_opt_t *opt, int argc, char *argv[]);
const char *sipdump_opt_cmd_usage(const char* exec_name);

/*!
  \brief 从命令行中解析配置
  \param opt 配置句柄
  \param path 配置文件路径
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_config_load(sipdump_opt_t *opt, const char *path);

/*!
  \brief 设置日志名
  \param opt 配置句柄
  \param name 名字
  \return 成功返回模式，失败返回NULL
*/
apr_status_t sipdump_opt_log_name_set(sipdump_opt_t *opt, const char *name);
const char *sipdump_opt_log_name_get(sipdump_opt_t *opt);

/*!
  \brief 设置日志模式
  \param opt 配置句柄
  \param mode 模式
  \return 成功返回模式，失败返回NULL
*/
apr_status_t sipdump_opt_log_mode_set(sipdump_opt_t *opt, const char *mode);
const char *sipdump_opt_log_mode_get(sipdump_opt_t *opt);

/*!
  \brief 设置日志设备
  \param opt 配置句柄
  \param facility 日志设备
  \return 成功返回日志设备，失败返回NULL
*/
apr_status_t sipdump_opt_log_facility_set(sipdump_opt_t *opt, const char *facility);
void* sipdump_opt_log_facility_get(sipdump_opt_t *opt);

/*!
  \brief 设置日志等级
  \param opt 配置句柄
  \param priority 日志等级
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_log_priority_set(sipdump_opt_t *opt, const char *priority);
int sipdump_opt_log_priority_get(sipdump_opt_t *opt);

/*!
  \brief 设置抓包网卡名称
  \param opt 配置句柄
  \param name 网卡名
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_eth_name_set(sipdump_opt_t *opt, const char *name);
const char *sipdump_opt_eth_name_get(sipdump_opt_t *opt);

/*!
  \brief 设置读取pcap文件名称
  \param opt 配置句柄
  \param name pcap文件名
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_pcap_name_set(sipdump_opt_t *opt, const char *name);
const char *sipdump_opt_pcap_name_get(sipdump_opt_t *opt);

/*!
  \brief 设置PCAP网卡过滤
  \param opt 配置句柄
  \param filter 过滤表达式
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_pcap_filter_set(sipdump_opt_t *opt, const char *filter);
const char *sipdump_opt_pcap_filter_get(sipdump_opt_t *opt);

/*!
  \brief 设置SIP方法名过滤（只保存过滤的方法）
  \param opt 配置句柄
  \param filter 方法组合字符串，按'|'分隔，例如 "INVITE|REGISTER"，若为空字符串，则表示不过滤，默认INVITE
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_sip_method_filter_set(sipdump_opt_t *opt, const char *filter);
int sipdump_opt_sip_method_filter_test(sipdump_opt_t *opt, int method);

/*!
  \brief 设置号码过滤（只保存过滤的号码）
  \param opt 配置句柄
  \param filter 号码正则表达式，若为空字符串，则表示不过滤，默认不过滤
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_number_filter_set(sipdump_opt_t *opt, const char *filter);
int sipdump_opt_number_filter_test(sipdump_opt_t *opt, const char *number);

/*!
  \brief 设置存储目录
  \param opt 配置句柄
  \param path 路径
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_pcap_record_path_set(sipdump_opt_t *opt, const char *path);
const char *sipdump_opt_pcap_record_path_get(sipdump_opt_t *opt);

/*!
  \brief 设置会话超时时间
  \param opt 配置句柄
  \param timeout 超时时间，单位：秒
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_limit_time_set(sipdump_opt_t *opt, apr_int64_t timeout);
apr_int64_t sipdump_opt_limit_time_get(sipdump_opt_t *opt);

/*!
  \brief 设置混杂模式
  \param opt 配置句柄
  \param promisc 混杂模式，0非混杂，1混杂
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_promisc_set(sipdump_opt_t *opt, int promisc);
int sipdump_opt_promisc_get(sipdump_opt_t *opt);

/*!
  \brief 设置抓RTP包标记
  \param opt 配置句柄
  \param rtp_filter rtp组合 @see sipdump_rtp_capture_e组合
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_rtp_filter_set(sipdump_opt_t *opt, const char *rtp_filter);
int sipdump_opt_rtp_filter_get(sipdump_opt_t *opt);
int sipdump_opt_rtp_filter_test(sipdump_opt_t *opt, int test);

/*!
  \brief 设置抓pcap buffer大小
  \param opt 配置句柄
  \param pcap_buffer_size pcap buffer大小
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_pcap_buffer_size_set(sipdump_opt_t *opt, int pcap_buffer_size);
int sipdump_opt_pcap_buffer_size_get(sipdump_opt_t *opt);

/*!
  \brief 设置写pcap包，是否立即刷新
  \param opt 配置句柄
  \param pcap_flush 1立即刷新，0不立即刷新
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_pcap_flush_set(sipdump_opt_t *opt, int pcap_flush);
int sipdump_opt_pcap_flush_get(sipdump_opt_t *opt);

/*!
  \brief 设置pid文件路径
  \param opt 配置句柄
  \param pid_file pid文件
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_pid_file_set(sipdump_opt_t *opt, const char *pid_file);
const char *sipdump_opt_pid_file_get(sipdump_opt_t *opt);

/*!
  \brief 获取IP组
  \param opt 配置句柄
  \param ip 目标IP
  \param ipgroup 目标IP所在的IP组
  \return 成功返回APR_SUCCESS，失败返回错误码
*/
apr_status_t sipdump_opt_ipgroup_get(sipdump_opt_t *opt, uint32_t ip, const sipdump_ipgroup_item_t **ipgroup);


APR_END_DECLS

#endif