#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include "dnssec.h"

#define LEN(a) (sizeof(a) / sizeof((a)[0]))

static size_t
find_string(const char *str[], size_t len, const char *s)
{
	for (size_t i = 1; i < len; ++i) {
		if (str[i] && strcmp(str[i], s) == 0)
			return i;
	}
	return 0;
}

static const char *type_names[] = {
	[TYPE_A]      = "A",
	[TYPE_NS]     = "NS",
	[TYPE_CNAME]  = "CNAME",
	[TYPE_SOA]    = "SOA",
	[TYPE_MX]     = "MX",
	[TYPE_AAAA]   = "AAAA",
	[TYPE_SRV]    = "SRV",
	[TYPE_DS]     = "DS",
	[TYPE_SSHFP]  = "SSHFP",
	[TYPE_RRSIG]  = "RRSIG",
	[TYPE_NSEC]   = "NSEC",
	[TYPE_DNSKEY] = "DNSKEY",
	[TYPE_TLSA]   = "TLSA",
};

int
type_from_string(const char *s)
{
	int type = find_string(type_names, LEN(type_names), s);
	if (!type && strncmp(s, "TYPE", 4) == 0) {
		char *end;
		type = strtoul(s + 4, &end, 10);
		if (*end)
			type = 0;
	}
	return type;
}

const char *
type_to_string(int type)
{
	static char buf[4 + 5 + 1];

	if (type < LEN(type_names) && type_names[type])
		return type_names[type];
	snprintf(buf, sizeof(buf), "TYPE%d", type);
	return buf;
}

static const char *class_names[] = {
	[CLASS_IN] = "IN",
};

int
class_from_string(const char *s)
{
	int class = find_string(class_names, LEN(class_names), s);
	if (!class && strncmp(s, "CLASS", 5) == 0) {
		char *end;
		class = strtoul(s + 5, &end, 10);
		if (*end)
			class = 0;
	}
	return class;
}

const char *
class_to_string(int class)
{
	static char buf[5 + 5 + 1];

	if (class < LEN(class_names) && class_names[class])
		return class_names[class];
	snprintf(buf, sizeof(buf), "CLASS%d", class);
	return buf;
}

static const char *algorithm_names[] = {
	[ALGORITHM_RSASHA1]         = "RSASHA1",
	[ALGORITHM_RSASHA256]       = "RSASHA256",
	[ALGORITHM_RSASHA512]       = "RSASHA512",
	[ALGORITHM_ECDSAP256SHA256] = "ECDSAP256SHA256",
	[ALGORITHM_ECDSAP384SHA384] = "ECDSAP384SHA384",
};

int
algorithm_from_string(const char *s)
{
	size_t i = find_string(algorithm_names, LEN(algorithm_names), s);
	if (i == -1)
		errx(1, "unknown algorithm '%s'", s);
	return i;
}

const char *
algorithm_to_string(int algorithm)
{
	return algorithm_names[algorithm];
}

static const char *digest_names[] = {
	[DIGEST_SHA1] = "SHA1",
	[DIGEST_SHA256] = "SHA256",
	[DIGEST_SHA384] = "SHA384",
};

int
digest_from_string(const char *s)
{
	size_t i = find_string(digest_names, LEN(digest_names), s);
	if (i == -1)
		errx(1, "unknown digest '%s'", s);
	return i;
}

size_t
dname_parse(const char *s, char **end, unsigned char dn[static DNAME_MAX], const unsigned char *origin, size_t origin_len)
{
	size_t len = 0, label_len;
	int rel;

	if (s[0] == '@') {
		++s;
		rel = 1;
		goto out;
	}
	for (;;) {
		label_len = 0;
		switch (s[0]) {
		case '.':
			if (len != 0)
				return 0;
			++s;
			rel = 0;
			goto out;
		case ' ':
		case '\t':
		case '\0':
			if (len == 0)
				return 0;
			rel = 0;
			goto out;
		case '"':
			while (*++s != '"') {
				if (*s == '\\')
					++s;
				if (len + label_len == DNAME_MAX - 2 || label_len == LABEL_MAX)
					return 0;
				dn[len + 1 + label_len++] = *s;
			}
			++s;
			break;
		default:
			while (*s && *s != ' ' && *s != '\t' && *s != '.') {
				int c;
				if (*s == '\\' && isdigit(*++s)) {
					if (!isdigit(s[1]) || !isdigit(s[2]))
						return 0;
					c = (s[0] - '0') * 100 + (s[1] - '0') * 10 + (s[2] - '0');
					s += 3;
				} else if (*s) {
					c = *s++;
				} else {
					return 0;
				}
				if (len + label_len == DNAME_MAX - 2 || label_len == LABEL_MAX)
					return 0;
				dn[len + 1 + label_len++] = c;
			}
		}
		if (label_len == 0)
			return 0;
		dn[len] = label_len;
		len += 1 + label_len;
		if (*s != '.') {
			rel = 1;
			break;
		}
		++s;
	}
out:
	if (*s && *s != ' ' && *s != '\t')
		return 0;
	if (rel) {
		if (!origin_len || len + origin_len > DNAME_MAX)
			return 0;
		memcpy(dn + len, origin, origin_len);
		len += origin_len;
	} else {
		dn[len++] = 0;
	}
	if (end)
		*end = (char *)s;
	return len;
}

int
dname_compare(const unsigned char *n1, const unsigned char *n2)
{
	unsigned char l1[DNAME_MAX], l2[DNAME_MAX], *p1 = l1, *p2 = l2;
	size_t l;
	int r;

	/* get label lengths */
	for (; *n1; n1 += 1 + *n1)
		*p1++ = *n1;
	for (; *n2; n2 += 1 + *n2)
		*p2++ = *n2;

	for (; p1 > l1 && p2 > l2; --n1, --n2) {
		l = *--p1 <= *--p2 ? *p1 : *p2;
		r = memcmp(n1 -= *p1, n2 -= *p2, l);
		if (r != 0)
			return r;
		if (l < *p1)
			return 1;
		if (l < *p2)
			return -1;
	}
	return (p1 > l1) - (p2 > l2);
}

int
dname_print(const unsigned char *dn)
{
	for (; *dn; dn += 1 + *dn) {
		if (fwrite(dn + 1, 1, *dn, stdout) != *dn || fputc('.', stdout) == EOF)
			return -1;
	}
	return 0;
}

int
dname_labels(const unsigned char *dn)
{
	int labels = 0;

	for (; *dn; dn += 1 + *dn)
		++labels;
	return labels;
}

struct dnskey *
dnskey_new(unsigned flags, const struct key *sk)
{
	br_ec_public_key pk;
	unsigned char buf[BR_EC_KBUF_PUB_MAX_SIZE];
	struct dnskey *k;

	switch (sk->algorithm) {
	case ALGORITHM_RSASHA1:
	case ALGORITHM_RSASHA256:
	case ALGORITHM_RSASHA512:;
		uint32_t e = br_rsa_compute_pubexp_get_default()(&sk->rsa);
		if (!e)
			errx(1, "failed to compute public exponent of RSA key");
		size_t nlen = br_rsa_compute_modulus_get_default()(NULL, &sk->rsa);
		if (!nlen)
			errx(1, "failed to compute public modulus of RSA key");
		if (!(k = malloc(sizeof(*k) + 5 + nlen)))
			err(1, "malloc");
		/* leading zeros in exponent are prohibited */
		for (k->data[0] = 4; !(e & 0xff000000); --k->data[0])
			e <<= 8;
		k->data_len = 1 + k->data[0] + nlen;
		memcpy(k->data + 1, &(uint32_t){htonl(e)}, k->data[0]);
		br_rsa_compute_modulus_get_default()(k->data + 1 + k->data[0], &sk->rsa);
		break;
	case ALGORITHM_ECDSAP256SHA256:
		if (br_ec_compute_pub(br_ec_get_default(), &pk, buf, &sk->ec) != 65)
			errx(1, "unexpected public key size");
		if (!(k = malloc(sizeof(*k) + 64)))
			err(1, "malloc");
		k->data_len = 64;
		memcpy(k->data, buf + 1, 64);
		break;
	case ALGORITHM_ECDSAP384SHA384:
		if (br_ec_compute_pub(br_ec_get_default(), &pk, buf, &sk->ec) != 97)
			errx(1, "unexpected public key size");
		if (!(k = malloc(sizeof(*k) + 96)))
			err(1, "malloc");
		k->data_len = 96;
		memcpy(k->data, buf + 1, 96);
		break;
	default:
		errx(1, "unsupported algorithm %s", algorithm_to_string(sk->algorithm));
	}
	k->flags = flags;
	k->algorithm = sk->algorithm;
	k->protocol = 3;
	return k;
}

unsigned
dnskey_tag(const struct dnskey *k)
{
	unsigned long x;
	const unsigned char *p;
	size_t i;

	x = k->flags + (k->protocol << 8) + k->algorithm;
	for (i = 0, p = k->data; i < k->data_len; ++p, ++i)
		x += i & 1 ? *p : (unsigned long)*p << 8;
	return (x + (x >> 16)) & 0xffff;
}
