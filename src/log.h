#ifndef PORTSCANNER_LOG_H
#define PORTSCANNER_LOG_H
#include <syslog.h>
#include <string.h>
#include <errno.h>

/* Обертки для более удобной отправки сообщений */

#define log_debug(fmt, ...)     syslog(LOG_DEBUG,   fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)      syslog(LOG_INFO,    fmt, ##__VA_ARGS__)
#define log_notice(fmt, ...)    syslog(LOG_NOTICE,  fmt, ##__VA_ARGS__)
#define log_warning(fmt, ...)   syslog(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_err(fmt, ...)       syslog(LOG_ERR,     fmt, ##__VA_ARGS__)
#define log_crit(fmt, ...)      syslog(LOG_CRIT,    fmt, ##__VA_ARGS__)
#define log_alert(fmt, ...)     syslog(LOG_ALERT,   fmt, ##__VA_ARGS__)
#define log_emerg(fmt, ...)     syslog(LOG_EMERG,   fmt, ##__VA_ARGS__)

/* Обертки для дополнительного логирования errno */
#define plog_debug(fmt, ...)     log_debug  (fmt ": %s (%d)", ##__VA_ARGS__, strerror(errno), errno)
#define plog_info(fmt, ...)      log_info   (fmt ": %s (%d)", ##__VA_ARGS__, strerror(errno), errno)
#define plog_notice(fmt, ...)    log_notice (fmt ": %s (%d)", ##__VA_ARGS__, strerror(errno), errno)
#define plog_warning(fmt, ...)   log_warning(fmt ": %s (%d)", ##__VA_ARGS__, strerror(errno), errno)
#define plog_err(fmt, ...)       log_err    (fmt ": %s (%d)", ##__VA_ARGS__, strerror(errno), errno)
#define plog_crit(fmt, ...)      log_crit   (fmt ": %s (%d)", ##__VA_ARGS__, strerror(errno), errno)
#define plog_alert(fmt, ...)     log_alert  (fmt ": %s (%d)", ##__VA_ARGS__, strerror(errno), errno)
#define plog_emerg(fmt, ...)     log_emerg  (fmt ": %s (%d)", ##__VA_ARGS__, strerror(errno), errno)

#endif //PORTSCANNER_LOG_H
