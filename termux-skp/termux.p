--- a/sk-usbhid.c	2025-05-26 09:56:07.796244095 +0900
+++ b/sk-usbhid.c	2025-05-26 10:03:28.740244121 +0900
@@ -17,6 +17,7 @@
  */
 
 #include "includes.h"
+#include "termux-io.h"
 
 #ifdef ENABLE_SK_INTERNAL
 
@@ -49,7 +50,6 @@
 #include <openssl/ec.h>
 #include <openssl/ecdsa.h>
 #include <openssl/evp.h>
-#include "openbsd-compat/openssl-compat.h"
 #endif /* WITH_OPENSSL */
 
 #include <fido.h>
@@ -135,35 +135,6 @@ int sk_sign(uint32_t alg, const uint8_t
 int sk_load_resident_keys(const char *pin, struct sk_option **options,
     struct sk_resident_key ***rks, size_t *nrks);
 
-static void skdebug(const char *func, const char *fmt, ...)
-    __attribute__((__format__ (printf, 2, 3)));
-
-static void
-skdebug(const char *func, const char *fmt, ...)
-{
-#if !defined(SK_STANDALONE)
-	char *msg;
-	va_list ap;
-
-	va_start(ap, fmt);
-	xvasprintf(&msg, fmt, ap);
-	va_end(ap);
-	debug("%s: %s", func, msg);
-	free(msg);
-#elif defined(SK_DEBUG)
-	va_list ap;
-
-	va_start(ap, fmt);
-	fprintf(stderr, "%s: ", func);
-	vfprintf(stderr, fmt, ap);
-	fputc('\n', stderr);
-	va_end(ap);
-#else
-	(void)func; /* XXX */
-	(void)fmt; /* XXX */
-#endif
-}
-
 uint32_t
 sk_api_version(void)
 {
@@ -176,6 +147,13 @@ sk_open(const char *path)
 	struct sk_usbhid *sk;
 	int r;
 
+  fido_dev_io_t io = {
+		&fido_termux_open,
+		&fido_termux_close,
+		&fido_termux_read,
+		&fido_termux_write,
+	};
+
 	if (path == NULL) {
 		skdebug(__func__, "path == NULL");
 		return NULL;
@@ -195,6 +173,9 @@ sk_open(const char *path)
 		free(sk);
 		return NULL;
 	}
+
+  fido_dev_set_io_functions(sk->dev, &io);
+
 	if ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
 		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
 		    fido_strerr(r));
@@ -562,39 +543,13 @@ static struct sk_usbhid *
 sk_probe(const char *application, const uint8_t *key_handle,
     size_t key_handle_len, int probe_resident)
 {
-	struct sk_usbhid *sk;
-	fido_dev_info_t *devlist;
-	size_t ndevs;
-	int r;
+  int rc = 0;
+  char path[1024];
+  if ((rc = termux_get_first_usb_device_path(path, sizeof(path))) < 0) {
+    return NULL;
+  }
 
-#ifdef HAVE_CYGWIN
-	if (!probe_resident && (sk = sk_open("windows://hello")) != NULL)
-		return sk;
-#endif /* HAVE_CYGWIN */
-	if ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == NULL) {
-		skdebug(__func__, "fido_dev_info_new failed");
-		return NULL;
-	}
-	if ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
-	    &ndevs)) != FIDO_OK) {
-		skdebug(__func__, "fido_dev_info_manifest failed: %s",
-		    fido_strerr(r));
-		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
-		return NULL;
-	}
-	skdebug(__func__, "%zu device(s) detected", ndevs);
-	if (ndevs == 0) {
-		sk = NULL;
-	} else if (application != NULL && key_handle != NULL) {
-		skdebug(__func__, "selecting sk by cred");
-		sk = sk_select_by_cred(devlist, ndevs, application, key_handle,
-		    key_handle_len);
-	} else {
-		skdebug(__func__, "selecting sk by touch");
-		sk = sk_select_by_touch(devlist, ndevs);
-	}
-	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
-	return sk;
+  return sk_open(path);
 }
 
 #ifdef WITH_OPENSSL
