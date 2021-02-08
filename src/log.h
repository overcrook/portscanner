#ifndef PORTSCANNER_LOG_H
#define PORTSCANNER_LOG_H
#include <syslog.h>
#include <string.h>
#include <errno.h>

/* Обертки для более удобной отправки сообщений */

#define log_debug(fmt, args...)     syslog(LOG_DEBUG,   fmt, ##args)
#define log_info(fmt, args...)      syslog(LOG_INFO,    fmt, ##args)
#define log_notice(fmt, args...)    syslog(LOG_NOTICE,  fmt, ##args)
#define log_warning(fmt, args...)   syslog(LOG_WARNING, fmt, ##args)
#define log_err(fmt, args...)       syslog(LOG_ERR,     fmt, ##args)
#define log_crit(fmt, args...)      syslog(LOG_CRIT,    fmt, ##args)
#define log_alert(fmt, args...)     syslog(LOG_ALERT,   fmt, ##args)
#define log_emerg(fmt, args...)     syslog(LOG_EMERG,   fmt, ##args)

/* Обертки для дополнительного логирования errno */
#define plog_debug(fmt, args...)     log_debug  (fmt ": %s (%d)", ##args, strerror(errno), errno)
#define plog_info(fmt, args...)      log_info   (fmt ": %s (%d)", ##args, strerror(errno), errno)
#define plog_notice(fmt, args...)    log_notice (fmt ": %s (%d)", ##args, strerror(errno), errno)
#define plog_warning(fmt, args...)   log_warning(fmt ": %s (%d)", ##args, strerror(errno), errno)
#define plog_err(fmt, args...)       log_err    (fmt ": %s (%d)", ##args, strerror(errno), errno)
#define plog_crit(fmt, args...)      log_crit   (fmt ": %s (%d)", ##args, strerror(errno), errno)
#define plog_alert(fmt, args...)     log_alert  (fmt ": %s (%d)", ##args, strerror(errno), errno)
#define plog_emerg(fmt, args...)     log_emerg  (fmt ": %s (%d)", ##args, strerror(errno), errno)

#endif //PORTSCANNER_LOG_H
