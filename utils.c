#include "utils.h"

void
skdebug(const char *func, const char *fmt, ...)
{
#if defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#else
	(void)func; /* XXX */
	(void)fmt; /* XXX */
#endif
}

