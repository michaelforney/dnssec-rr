#include <err.h>
#include "dnssec.h"

static int
base16_value(int c)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	switch (c) {
	case 'a': case 'A': return 10;
	case 'b': case 'B': return 11;
	case 'c': case 'C': return 12;
	case 'd': case 'D': return 13;
	case 'e': case 'E': return 14;
	case 'f': case 'F': return 15;
	}
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
