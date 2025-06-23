build:
	mkdir -p ssh
	cp ./openssh-portable/sk-api.h ssh/
	cp ./openssh-portable/misc.h ssh/
	cp ./openssh-portable/ssherr.h ssh/
	cp ./openssh-portable/openbsd-compat/recallocarray.c ssh/
	cp ./openssh-portable/openbsd-compat/freezero.c ssh/
	cp ./openssh-portable/openbsd-compat/explicit_bzero.c ssh/
	# touch ssh/log.h

	cp ./openssh-portable/sk-usbhid.c .
	patch -p1 -i termux.p
	# touch xmalloc.h
	# touch match.h
	$(CC) \
		$(CFLAGS) \
		-I ssh \
		-I . \
		-D ENABLE_SK_INTERNAL \
		-D SK_STANDALONE \
		-D WITH_OPENSSL \
		-D OPENSSL_HAS_ECC \
		-D HAVE_FIDO_CRED_SET_CLIENTDATA \
		-D HAVE_FIDO_ASSERT_SET_CLIENTDATA \
		-D HAVE_FIDO_DEV_IS_WINHELLO \
		$(shell pkg-config --cflags --libs libfido2) $(shell pkg-config --cflags --libs hidapi-libusb) $(shell pkg-config --cflags --libs libusb-1.0) \
		yyjson.c \
		sk-usbhid.c ssh/freezero.c ssh/recallocarray.c ssh/explicit_bzero.c skdebug.c \
		termux.c termux-io.c \
		-shared -o termux-skp.so

