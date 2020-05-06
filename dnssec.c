#include <arpa/inet.h>
#include <assert.h>
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
	return -1;
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
	[TYPE_RRSIG]  = "RRSIG",
	[TYPE_NSEC]   = "NSEC",
	[TYPE_DNSKEY] = "DNSKEY",
	[TYPE_TLSA]   = "TLSA",
};

int
type_from_string(const char *s)
{
	size_t i = find_string(type_names, LEN(type_names), s);
	if (i == -1)
		errx(1, "unknown type '%s'", s);
	return i;
}

const char *
type_to_string(int type)
{
	return type_names[type];
}

static const char *class_names[] = {
	[CLASS_IN] = "IN",
};

int
class_from_string(const char *s)
{
	size_t i = find_string(class_names, LEN(class_names), s);
	if (i == -1)
		errx(1, "unknown class '%s'", s);
	return i;
}

const char *
class_to_string(int class)
{
	return class_names[class];
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

void
dname_hash(const char *name, const br_hash_class **hc)
{
	const char *p;

	while ((p = strchr(name, '.'))) {
		if (p - name > 63)
			errx(1, "domain name label is too long");
		(*hc)->update(hc, &(uint8_t){p - name}, 1);
		(*hc)->update(hc, name, p - name);
		name = p + 1;
	}
	if (*name)
		errx(1, "domain name does not end with root label");
	(*hc)->update(hc, &(uint8_t){0}, 1);
}

unsigned char *
dname_encode(unsigned char *dst, const char *src)
{
	const char *p;

	while ((p = strchr(src, '.'))) {
		if (p - src > 63)
			errx(1, "domain name label is too long");
		*dst++ = p - src;
		memcpy(dst, src, p - src);
		dst += p - src;
		src = p + 1;
	}
	if (*src)
		errx(1, "domain name does not end with root label");
	*dst++ = 0;
	return dst;
}

int
dname_labels(const char *name)
{
	int labels;

	if (strcmp(name, ".") == 0)
		return 0;
	for (labels = 0; *name; ++name, ++labels) {
		name = strchr(name, '.');
		assert(name);
	}
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
