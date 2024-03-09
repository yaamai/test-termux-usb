#ifndef TERMUX_H
#define TERMUX_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include "yyjson.h"
#include "utils.h"

typedef struct termux_api_client_s {
  char input_addr[100];  // This program reads from it.
  char output_addr[100]; // This program writes to it.
  int input_server_socket;
  int output_server_socket;
  int fd;
  char buffer[1024];
} termux_api_client_t;

#ifndef PREFIX
# define PREFIX "/data/data/com.termux/files/usr"
#endif

int termux_open_usb_device(int* fd, const char* path);

#endif /* TERMUX_H */
