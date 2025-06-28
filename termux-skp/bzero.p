--- a/ssh/explicit_bzero.c	2025-06-28 23:04:27.572703959 +0900
+++ b/ssh/explicit_bzero.c	2025-06-28 23:05:19.146436095 +0900
@@ -39,7 +39,12 @@ explicit_bzero(void *p, size_t n)
  * Indirect bzero through a volatile pointer to hopefully avoid
  * dead-store optimisation eliminating the call.
  */
+
+#ifndef bzero
 static void (* volatile ssh_bzero)(void *, size_t) = bzero;
+#else
+static void (* volatile ssh_bzero)(void *, size_t) = __bionic_bzero;
+#endif
 
 void
 explicit_bzero(void *p, size_t n)
