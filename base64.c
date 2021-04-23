#include <err.h>
#include "dnssec.h"

void
base64_encode(char *dst, const unsigned char *src, size_t len)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	for (size_t i = 0; i < len; i += 3, dst += 4) {
		unsigned long x = (unsigned long)src[i] << 16;
		dst[3] = i + 2 >= len ? '=' : b64[(x |= src[i + 2]) & 0x3f];
		dst[2] = i + 1 >= len ? '=' : b64[(x |= (unsigned long)src[i + 1] << 8) >> 6 & 0x3f];
		dst[1] = b64[x >> 12 & 0x3f];
		dst[0] = b64[x >> 18];
	}
	*dst = '\0';
}

size_t
base64_decode(unsigned char *dst, const char *src)
{
	static const char b64[] = {
		['A'] =  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,
		        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
		['a'] = 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
		['0'] = 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
		['+'] = 62,
		['/'] = 63,
	};
	unsigned long x;
	size_t i, len;
	unsigned c, pad = 0;

	for (i = 0, x = 0, len = 0; src[i]; ++i) {
		c = (unsigned char)src[i];
		if (c == '=' && (!src[i + 1] || (src[i + 1] == '=' && !src[i + 2])))
			++pad;
		else if (c >= sizeof(b64) || (!b64[c] && c != 'A'))
			errx(1, "invalid base64 character '%c'", c);
		x = x << 6 | b64[c];
		if (i % 4 == 3) {
			dst[len + 2] = x & 0xff; x >>= 8;
			dst[len + 1] = x & 0xff; x >>= 8;
			dst[len + 0] = x & 0xff;
			len += 3;
		}
	}
	if (i % 4 != 0)
		errx(1, "truncated base64");
	return len - pad;
}
