MODULE := termux-skp.so

all:	$(MODULE)

$(MODULE):
	$(CC) \
		$(CFLAGS) -I src \
		-D ENABLE_SK_INTERNAL \
		-D WITH_OPENSSL \
    -D OPENSSL_HAS_ECC \
		-D HAVE_FIDO_CRED_SET_CLIENTDATA \
		-D HAVE_FIDO_ASSERT_SET_CLIENTDATA \
		-D HAVE_FIDO_DEV_IS_WINHELLO \
		-shared -fPIC \
		yyjson.c sk-usbhid.c termux.c utils.c termux-io.c \
		$(shell pkg-config --cflags --libs libfido2) $(shell pkg-config --cflags --libs hidapi-libusb) $(shell pkg-config --cflags --libs libusb-1.0) -lbsd \
		$(LDFLAGS) \
		-o $(MODULE)
	readelf -d $(MODULE)

install:
	env
	install -Dm644 $(MODULE) $(PREFIX)/lib/
