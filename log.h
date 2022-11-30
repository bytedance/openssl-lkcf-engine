#ifndef KCTL_ENGINE_LOG_H
#define KCTL_ENGINE_LOG_H

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>

#ifndef gettid
#define gettid() syscall(SYS_gettid)
#endif

extern const char kctl_log_level_to_tag[];

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERROR 3

#define LOG_BUFF_SIZE 4096

#ifndef LOG_LEVEL 
#define LOG_LEVEL LOG_LEVEL_DEBUG
#endif

typedef void (*kctl_logger) (int log_level, const char *msg);

kctl_logger kctl_set_logger(kctl_logger logger);
void kctl_log_message_impl(int log_level, const char* fmt, ...);

static inline char* kctl_log_fmt_time(char* buff, size_t len)
{
  struct tm tm_info;
  struct timeval tv;
  int offset;

  gettimeofday(&tv, NULL);

  localtime_r(&tv.tv_sec, &tm_info);

  offset = strftime(buff, len, "%Y%m%d %H:%M:%S", &tm_info);
  snprintf(buff + offset, len - offset, ".%06lu", tv.tv_usec);
  return buff;
}

#define VA_ARGS(...) , ##__VA_ARGS__
#define log_impl(log_level, fmt, ...) \
	while (log_level >= LOG_LEVEL) { \
		char timestr[48]; \
		pid_t tid = gettid(); \
		kctl_log_message_impl(log_level, "%c%s %d %s:%d] " fmt "\n", \
		                      kctl_log_level_to_tag[log_level], \
		                      kctl_log_fmt_time(timestr, sizeof(timestr)), \
		                      tid, __FILE__, __LINE__ VA_ARGS(__VA_ARGS__)); \
		break; \
	}

#define log_debug(fmt, ...) log_impl(LOG_LEVEL_DEBUG, fmt, __VA_ARGS__)
#define log_info(fmt, ...)   log_impl(LOG_LEVEL_INFO, fmt , __VA_ARGS__)
#define log_warn(fmt, ...)   log_impl(LOG_LEVEL_WARN, fmt , __VA_ARGS__)
#define log_error(fmt, ...)   log_impl(LOG_LEVEL_ERROR, fmt , __VA_ARGS__)

#endif  // KCTL_ENGINE_LOG_H
