#ifndef SKDEBUG_H
#define SKDEBUG_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void skdebug(const char *func, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

#endif /* SKDEBUG_H */
