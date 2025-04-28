#include "termux-io.h"

struct hidapi_context {
	void *handle;
	size_t report_in_len;
	size_t report_out_len;
};


void *fido_termux_open(const char *path) {
  skdebug(__func__, "opening security key %s with hidapi-libusb", path);
  struct hidapi_context *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL) {
		return (NULL);
	}

  int fd = 0;
  int rc = 0;
  rc = termux_request_usb_device(&fd, path);
  if (rc != 0) {
    skdebug(__func__, "failed to request usb device: %d", rc);
    return NULL;
  }

  rc = termux_open_usb_device(&fd, path);
  if (rc != 0) {
    skdebug(__func__, "failed to open usb device: %d", rc);
    return NULL;
  }

  libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
  ctx->handle = hid_libusb_wrap_sys_device((intptr_t)fd, -1);

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
