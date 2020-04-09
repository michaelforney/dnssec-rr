#include <err.h>
#include "dnssec.h"

void
base64_encode(char *dst, const unsigned char *src, size_t len)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	for (size_t i = 0; i < len; i += 3) {
		unsigned long n = src[i] << 16;
		if (i + 1 < len)
			n |= src[i + 1] << 8;
		if (i + 2 < len)
			n |= src[i + 2];
		*dst++ = b64[n >> 18];
		*dst++ = b64[n >> 12 & 0x3f];
		*dst++ = i + 1 < len ? b64[n >> 6 & 0x3f] : '=';
		*dst++ = i + 2 < len ? b64[n & 0x3f] : '=';
	}
	*dst++ = '\0';
}

static unsigned long
base64_value(int c)
{
	if ('A' <= c && c <= 'Z')
		return c - 'A';
	if ('a' <= c && c <= 'z')
		return c - 'a' + 26;
	if ('0' <= c && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	if (c == '=')
		return 0;
	errx(1, "invalid base64 character '%c'", c);
}

size_t
base64_decode(unsigned char *dst, const char *src)
{
	unsigned char *p = dst;

	for (size_t i = 0; src[i]; i += 4) {
		unsigned long n = base64_value(src[i]) << 18 | base64_value(src[i + 1]) << 12 | base64_value(src[i + 2]) << 6 | base64_value(src[i + 3]);
		*p++ = n >> 16;
		if (src[i + 2] != '=')
			*p++ = n >> 8 & 0xff;
		if (src[i + 3] != '=')
			*p++ = n & 0xff;
	}
	return p - dst;
}
