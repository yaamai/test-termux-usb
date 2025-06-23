--- a/ssh/explicit_bzero.c	2025-06-23 01:52:35.479115651 +0000
+++ b/ssh/explicit_bzero.c	2025-06-23 01:52:37.847115651 +0000
@@ -23,6 +23,14 @@ explicit_bzero(void *p, size_t n)
 	(void)explicit_memset(p, 0, n);
 }
 
+#elif defined(__bionic_bzero)
+
+void
+explicit_bzero(void *p, size_t n)
+{
+  __bionic_bzero(p, n);
+}
+
 #elif defined(HAVE_MEMSET_S)
 
 void
