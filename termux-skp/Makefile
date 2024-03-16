MODULE := termux-skp.so

all:	$(MODULE)

$(MODULE):
	$(CC) \
		$(CFLAGS) -I src \
		-shared -fPIC \
		yyjson.c skp.c termux.c utils.c termux-io.c \
		$(shell pkg-config --cflags --libs libfido2) $(shell pkg-config --cflags --libs hidapi-libusb) $(shell pkg-config --cflags --libs libusb-1.0) \
		-o $(MODULE)
	patchelf --set-rpath '$$ORIGIN' $(MODULE)
	readelf -d $(MODULE)

install:
	env
	install -Dm644 $(MODULE) $(PREFIX)/lib/
