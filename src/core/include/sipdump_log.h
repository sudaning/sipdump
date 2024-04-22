
#ifndef SIPDUMP_LOG_H__
#define SIPDUMP_LOG_H__

#include <apr.h>
#include <apr_pools.h>

#ifdef SIPDUMP_USE_SYS_LOG
#include <syslog.h>
#endif

APR_BEGIN_DECLS

extern int g_priority;

enum sipdump_log_priority_e {
	SIPDUMP_PRIO_CRITICAL,  /** 致命 */
	SIPDUMP_PRIO_ERROR,     /** 错误 */
	SIPDUMP_PRIO_WARNING,   /** 告警 */
	SIPDUMP_PRIO_NOTICE,    /** 通知 */
	SIPDUMP_PRIO_INFO,      /** 信息 */
	SIPDUMP_PRIO_DEBUG,     /** 调试 */
	SIPDUMP_PRIO_TRACE,     /** 追踪 */
	SIPDUMP_PRIO_COUNT     	/** 最大计数 */
};

/** 日志级别 */
typedef enum sipdump_log_priority_e sipdump_log_priority_e;

apr_status_t sipdump_log_init(const char *name, const char* mod, void* facility);
apr_status_t sipdump_log_uninit();

/*!
  \brief 设置日志级别
  \param priority 级别（字符串）
  \return 日志级别
*/
sipdump_log_priority_e sipdump_log_priority_set(const char *priority);

/*!
  \brief 日志级别是否是trace
  \param priority 级别（字符串）
  \return 是TRUE，否FALSE
*/
int sipdump_log_priority_trace();

/** 使用日志宏，此函数外部不直接使用 */
void sipdump_log(const char *file, int line, sipdump_log_priority_e priority, const char *fmt, ...);

/*!
  \brief 记录日志
  \param priority 级别
  \param fmt 格式化
  \param ... 变参
  \return 无
*/
#define SIPDUMP_LOG(priority, fmt, ...) if (priority <= g_priority) sipdump_log(__FILE__, __LINE__, priority, fmt, ##__VA_ARGS__)

APR_END_DECLS

#endif