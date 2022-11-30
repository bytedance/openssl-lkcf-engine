#include "log.h"

#include <stdarg.h>

const char kctl_log_level_to_tag[] = {'D', 'I', 'W', 'E'};
static void default_logger(int log_level, const char *message)
{
	fprintf(stderr, "%s", message);
}

static kctl_logger g_logger = default_logger;

kctl_logger kctl_set_logger(kctl_logger logger)
{
	kctl_logger old_logger = g_logger;
	g_logger = logger;
	return old_logger;
}

void kctl_log_message_impl(int log_level, const char *fmt, ...)
{
	char buff[LOG_BUFF_SIZE];
	int ret;

	va_list ap;
	va_start(ap, fmt);
	ret = vsnprintf(buff, LOG_BUFF_SIZE, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		return;
	}
	g_logger(log_level, buff);
}
