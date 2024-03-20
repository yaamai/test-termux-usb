#include "termux.h"

void generate_uuid(char* str) {
    sprintf(str, "%x%x-%x-%x-%x-%x%x%x",
            /* 64-bit Hex number */
            arc4random(), arc4random(),
            /* 32-bit Hex number */
            (uint32_t) getpid(),
            /* 32-bit Hex number of the form 4xxx (4 is the UUID version) */
            ((arc4random() & 0x0fff) | 0x4000),
            /* 32-bit Hex number in the range [0x8000, 0xbfff] */
            arc4random() % 0x3fff + 0x8000,
            /*  96-bit Hex number */
            arc4random(), arc4random(), arc4random());
}

int make_am_base_argv(char** argv, size_t buflen, size_t* write, const char* input_addr, const char* output_addr, const char* api, const char* action) {
  char* base[] = {
    "am", "broadcast", "--user", "0", "-n", "com.termux.api/.TermuxApiReceiver",
    "--es", "socket_input", (char*)output_addr,
    "--es", "socket_output", (char*)input_addr,
    "--es", "api_method", (char*)api,
    "-a", (char*)action};

  size_t len = sizeof(base)/sizeof(char*);
  if (buflen <= len) return -1;

  memcpy(argv, base, sizeof(base));
  *write += sizeof(base)/sizeof(char*);

  return 0;
}

int execv_am_cmd(char** argv) {
  pid_t fork_result = fork();

  if (fork_result == -1) {
      perror("fork()");
      return -1;
  } else if (fork_result == 0) {
    execv(PREFIX "/bin/am", argv);
    perror("execv(\"" PREFIX "/bin/am\")");
    exit(1);
  }

  return 0;
}

int prepare_sockets(termux_api_client_t* client) {

    generate_uuid(client->input_addr);
    generate_uuid(client->output_addr);

    struct sockaddr_un input_addr = { .sun_family = AF_UNIX };
    struct sockaddr_un output_addr = { .sun_family = AF_UNIX };

    // Leave struct sockaddr_un.sun_path[0] as 0 and use the UUID
    // string as abstract linux namespace:
    strncpy(&input_addr.sun_path[1], client->input_addr, strlen(client->input_addr));
    strncpy(&output_addr.sun_path[1], client->output_addr, strlen(client->output_addr));

    client->input_server_socket = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (client->input_server_socket == -1) {
        perror("socket()");
        return -1;
    }
    client->output_server_socket = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (client->output_server_socket == -1) {
        perror("socket()");
        return -1;
    }

    int ret;
    ret = bind(client->input_server_socket, (struct sockaddr*) &input_addr,
               sizeof(sa_family_t) + strlen(client->input_addr) + 1);
    if (ret == -1) {
        perror("bind(input)");
        return ret;
    }

    ret = bind(client->output_server_socket, (struct sockaddr*) &output_addr,
               sizeof(sa_family_t) + strlen(client->output_addr) + 1);
    if (ret == -1) {
        perror("bind(output)");
        return ret;
    }

    if (listen(client->input_server_socket, 1) == -1) {
        perror("listen()");
        return -1;
    }

    if (listen(client->output_server_socket, 1) == -1) {
        perror("listen()");
        return -1;
    }
    return 0;
}

int termux_recv(termux_api_client_t* client) {

    skdebug(__func__, "start receiving result: %s", client->input_addr);
    struct sockaddr_un remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    int input_client_socket = accept(client->input_server_socket,
                                     (struct sockaddr*) &remote_addr,
                                     &addrlen);

    skdebug(__func__, "accept Termux:API connection");

    ssize_t len;
    size_t write_pos = 0;
    char buffer[1024];
    char cbuf[256];
    client->fd = -1;  // An optional file descriptor received through the socket
                      //
    struct iovec io = { .iov_base = buffer, .iov_len = sizeof(buffer) };
    struct msghdr msg = { 0 };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    while ((len = recvmsg(input_client_socket, &msg, 0)) > 0) {
        skdebug(__func__, "recvmsg: %d", len);
        struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
            if (cmsg->cmsg_type == SCM_RIGHTS) {
                client->fd = *((int *) CMSG_DATA(cmsg));
            }
        }

        // A file descriptor must be accompanied by a non-empty message,
        // so we use "@" when we don't want any output.
        if (client->fd != -1 && len == 1 && buffer[0] == '@') { len = 0; }

        if (write_pos + len < sizeof(client->buffer))  {
          memcpy(client->buffer+write_pos, buffer, len);
          write_pos += len;
        }
        msg.msg_controllen = sizeof(cbuf);
    }
    if (len < 0) return -1;
    return 0;
}

int termux_list_usb_devices(char* buffer, size_t buflen) {
  int rc = 0;
  termux_api_client_t* client;

	if ((client = calloc(1, sizeof(*client))) == NULL) {
		return -1;
	}

  if ((rc = prepare_sockets(client)) < 0) {
    return rc;
  }

  char** argv = malloc((sizeof(char*)) * 64);
  size_t argc = 0;
  if ((rc = make_am_base_argv(argv, 64, &argc, client->input_addr, client->output_addr, "Usb", "list")) < 0) {
    return rc;
  }
  argv[argc] = NULL;

  execv_am_cmd(argv);
  if ((rc = termux_recv(client)) < 0) {
    return rc;
  }

  strncpy(buffer, client->buffer, buflen);
  skdebug(__func__, "enumerated usb device: %s", buffer);

  close(client->input_server_socket);
  close(client->output_server_socket);
  free(client);

  return 0;
}

int termux_get_first_usb_device_path(char* buffer, size_t buflen) {
  int rc = 0;
  char json[1024];
  if ((rc = termux_list_usb_devices(json, sizeof(json))) < 0) {
    return rc;
  }

  yyjson_doc *doc = yyjson_read(json, strlen(json), 0);
  yyjson_val *root = yyjson_doc_get_root(doc);
  yyjson_val *path = yyjson_arr_get_first(root);

  strncpy(buffer, yyjson_get_str(path), buflen);
  skdebug(__func__, "found usb device: %s", buffer);

  return 0;
}

int termux_request_usb_device(int* fd, const char* path) {
  int rc = 0;
  termux_api_client_t* client;

	if ((client = calloc(1, sizeof(*client))) == NULL) {
		return -1;
	}

  if ((rc = prepare_sockets(client)) < 0) {
    return rc;
  }

  char** argv = malloc((sizeof(char*)) * 64);
  size_t argc = 0;
  if ((rc = make_am_base_argv(argv, 64, &argc, client->input_addr, client->output_addr, "Usb", "permission")) < 0) {
    return rc;
  }
  argv[argc++] = "--es";
  argv[argc++] = "device";
  argv[argc++] = (char*)path;
  argv[argc++] = "--ez";
  argv[argc++] = "request";
  argv[argc++] = "true";
  argv[argc] = NULL;

  execv_am_cmd(argv);
  if ((rc = termux_recv(client)) < 0) {
    return rc;
  }

  close(client->input_server_socket);
  close(client->output_server_socket);
  free(client);
  return 0;
}

int termux_open_usb_device(int* fd, const char* path) {
  int rc = 0;
  termux_api_client_t* client;

	if ((client = calloc(1, sizeof(*client))) == NULL) {
		return -1;
	}

  if ((rc = prepare_sockets(client)) < 0) {
    return rc;
  }

  char** argv = malloc((sizeof(char*)) * 64);
  size_t argc = 0;
  if ((rc = make_am_base_argv(argv, 64, &argc, client->input_addr, client->output_addr, "Usb", "open")) < 0) {
    return rc;
  }
  argv[argc++] = "--es";
  argv[argc++] = "device";
  argv[argc++] = (char*)path;
  argv[argc] = NULL;

  execv_am_cmd(argv);
  if ((rc = termux_recv(client)) < 0) {
    return rc;
  }

  *fd = client->fd;

  close(client->input_server_socket);
  close(client->output_server_socket);
  free(client);
  return 0;
}
