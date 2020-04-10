#include <err.h>
#include "dnssec.h"

static int
base16_value(int c)
{
	if ('A' <= c && c <= 'Z')
		return c - 'A' + 10;
	if ('a' <= c && c <= 'z')
		return c - 'a' + 10;
	if ('0' <= c && c <= '9')
		return c - '0';
	errx(1, "invalid base16 character '%c'", c);
}

size_t
base16_decode(unsigned char *dst, const char *src)
{
	unsigned char *p = dst;

	for (size_t i = 0; src[i]; i += 2) {
		if (!src[i + 1])
			errx(1, "truncated base16 string");
		*p++ = base16_value(src[i]) << 4 | base16_value(src[i + 1]);
	}
	return p - dst;
}
