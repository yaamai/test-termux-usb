#ifndef TERMUX_IO_H
#define TERMUX_IO_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include <hidapi/hidapi_libusb.h>
#include <fido.h>

#include "utils.h"

#ifndef PREFIX
# define PREFIX "/data/data/com.termux/files/usr"
#endif

void *fido_termux_open(const char *path);
void fido_termux_close(void *handle);
int fido_termux_read(void *handle, unsigned char *buf, size_t len, int ms);
int fido_termux_write(void *handle, const unsigned char *buf, size_t len);

#endif /* TERMUX_IO_H */
