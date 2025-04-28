#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include "skdebug.h"

int
xvasprintf(char **ret, const char *fmt, va_list ap);
void *
recallocarray(void *ptr, size_t oldnmemb, size_t newnmemb, size_t size);
void
freezero(void *ptr, size_t sz);

