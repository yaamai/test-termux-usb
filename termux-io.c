#include "termux-io.h"

struct hidapi_context {
	void *handle;
	size_t report_in_len;
	size_t report_out_len;
  char input_addr_str[100];  // This program reads from it.
  char output_addr_str[100]; // This program writes to it.
  int input_server_socket;
  int output_server_socket;
};

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

_Noreturn void exec_am_broadcast(const char* path,
                                 char* input_address_string,
                                 char* output_address_string)
{
    // Redirect stdout to /dev/null (but leave stderr open):
    //close(STDOUT_FILENO);
    //open("/dev/null", O_RDONLY);
    // Close stdin:
    //close(STDIN_FILENO);

    int const extra_args = 23; // Including ending NULL.
    char** child_argv = malloc((sizeof(char*)) * (extra_args+1));

    child_argv[0] = "am";
    child_argv[1] = "broadcast";
    child_argv[2] = "--user";
    child_argv[3] = "0";
    child_argv[4] = "-n";
    child_argv[5] = "com.termux.api/.TermuxApiReceiver";
    child_argv[6] = "--es";
    // Input/output are reversed for the java process (our output is its input):
    child_argv[7] = "socket_input";
    child_argv[8] = output_address_string;
    child_argv[9] = "--es";
    child_argv[10] = "socket_output";
    child_argv[11] = input_address_string;
    child_argv[12] = "--es";
    child_argv[13] = "api_method";
    child_argv[14] = "Usb";
    child_argv[15] = "-a";
    child_argv[16] = "open";
    child_argv[17] = "--es";
    child_argv[18] = "device";
    child_argv[19] = path;
    child_argv[20] = "--ez";
    child_argv[21] = "request";
    child_argv[22] = "true";

    // Copy the remaining arguments -2 for first binary and second api name:
    // memcpy(child_argv + extra_args, argv + 2, (argc-1) * sizeof(char*));

    // End with NULL:
    child_argv[extra_args] = NULL;

    // Use an a executable taking care of PATH and LD_LIBRARY_PATH:
    execv(PREFIX "/bin/am", child_argv);

    perror("execv(\"" PREFIX "/bin/am\")");
    exit(1);
}

int prepare_sockets(struct hidapi_context *ctx) {

    generate_uuid(ctx->input_addr_str);
    generate_uuid(ctx->output_addr_str);

    struct sockaddr_un input_addr = { .sun_family = AF_UNIX };
    struct sockaddr_un output_addr = { .sun_family = AF_UNIX };
    // Leave struct sockaddr_un.sun_path[0] as 0 and use the UUID
    // string as abstract linux namespace:
    strncpy(&input_addr.sun_path[1], ctx->input_addr_str, strlen(ctx->input_addr_str));
    strncpy(&output_addr.sun_path[1], ctx->output_addr_str, strlen(ctx->output_addr_str));

    ctx->input_server_socket = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (ctx->input_server_socket == -1) {
        perror("socket()");
        return -1;
    }
    ctx->output_server_socket = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (ctx->output_server_socket == -1) {
        perror("socket()");
        return -1;
    }

    int ret;
    ret = bind(ctx->input_server_socket, (struct sockaddr*) &input_addr,
               sizeof(sa_family_t) + strlen(ctx->input_addr_str) + 1);
    if (ret == -1) {
        perror("bind(input)");
        return ret;
    }

    ret = bind(ctx->output_server_socket, (struct sockaddr*) &output_addr,
               sizeof(sa_family_t) + strlen(ctx->output_addr_str) + 1);
    if (ret == -1) {
        perror("bind(output)");
        return ret;
    }

    if (listen(ctx->input_server_socket, 1) == -1) {
        perror("listen()");
        return -1;
    }

    if (listen(ctx->output_server_socket, 1) == -1) {
        perror("listen()");
        return -1;
    }
}

int termux_open_device(struct hidapi_context *ctx, const char* path) {
    pid_t fork_result = fork();
    if (fork_result == -1) {
        perror("fork()");
        return -1;
    } else if (fork_result == 0) {
        exec_am_broadcast(path, ctx->input_addr_str, ctx->output_addr_str);
    }
}

int termux_read_fd(struct hidapi_context *ctx) {
    struct sockaddr_un remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    int input_client_socket = accept(ctx->input_server_socket,
                                     (struct sockaddr*) &remote_addr,
                                     &addrlen);

    ssize_t len;
    char buffer[1024];
    char cbuf[256];
    struct iovec io = { .iov_base = buffer, .iov_len = sizeof(buffer) };
    struct msghdr msg = { 0 };
    int fd = -1;  // An optional file descriptor received through the socket
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    while ((len = recvmsg(input_client_socket, &msg, 0)) > 0) {
        struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
            if (cmsg->cmsg_type == SCM_RIGHTS) {
                fd = *((int *) CMSG_DATA(cmsg));
            }
        }
        // A file descriptor must be accompanied by a non-empty message,
        // so we use "@" when we don't want any output.
        if (fd != -1 && len == 1 && buffer[0] == '@') { len = 0; }
        write(STDOUT_FILENO, buffer, len);
        msg.msg_controllen = sizeof(cbuf);
    }
    if (len < 0) perror("recvmsg()");
    return fd;
}


void *fido_termux_open(const char *path) {
  skdebug(__func__, "opening security key %s with hidapi-libusb", path);
  struct hidapi_context *ctx;


	if ((ctx = calloc(1, sizeof(*ctx))) == NULL) {
		return (NULL);
	}

  prepare_sockets(ctx);
  skdebug(__func__, "prepare termux api socket");
  termux_open_device(ctx, path);
  skdebug(__func__, "requested termux usb fd");
  int fd = termux_read_fd(ctx);
  skdebug(__func__, "usb fd = %d", fd);

  libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
  ctx->handle = hid_libusb_wrap_sys_device((intptr_t)fd, -1);
  // device = libusb_get_device(handle);
  // res = libusb_open(usb_dev, &dev->device_handle);
	// 					if (res < 0) {
	// 						LOG("can't open device\n");
	// 						break;
	// 					}
	// good_open = hidapi_initialize_device(dev, intf_desc, conf_desc);
	// if (!good_open)
	// 	libusb_close(dev->device_handle);

  // char aaa[128];
  // sprintf(aaa, "/proc/self/fd/%d", fd);

	if (ctx->handle == NULL) {
    skdebug(__func__, "failed to hid_open_path %x", ctx->handle);
		free(ctx);
		return (NULL);
	}

	ctx->report_in_len = ctx->report_out_len = CTAP_MAX_REPORT_LEN;

	return ctx;
}

void fido_termux_close(void *handle) {
  skdebug(__func__, "closing %x", handle);

	struct hidapi_context *ctx = handle;

	hid_close(ctx->handle);
	free(ctx);
}

int fido_termux_read(void *handle, unsigned char *buf, size_t len, int ms) {
	struct hidapi_context *ctx = handle;

	if (len != ctx->report_in_len) {
		skdebug(__func__, "len %zu", len);
		return -1;
	}

	return hid_read_timeout(ctx->handle, buf, len, ms);
  return 0;
}

int fido_termux_write(void *handle, const unsigned char *buf, size_t len) {
	struct hidapi_context *ctx = handle;

	if (len != ctx->report_out_len + 1) {
		skdebug(__func__, "len %zu", len);
		return -1;
	}

	return hid_write(ctx->handle, buf, len);
}
