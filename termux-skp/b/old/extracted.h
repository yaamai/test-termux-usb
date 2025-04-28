
int
xvasprintf(char **ret, const char *fmt, va_list ap);
/*
{
	int i;

	i = vasprintf(ret, fmt, ap);
	if (i < 0 || *ret == NULL)
		fatal("xvasprintf: could not allocate memory");
	return i;
}
*/
