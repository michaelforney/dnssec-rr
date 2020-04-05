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
	[ALGORITHM_ECDSAP256SHA256] = "ECDSAP256SHA256",
};

int
algorithm_from_string(const char *s)
{
	size_t i = find_string(algorithm_names, LEN(algorithm_names), s);
	if (i == -1)
		errx(1, "unknown algorithm '%s'", s);
	return i;
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

struct dnskey *
dnskey_new(unsigned flags, const struct key *sk)
{
	br_ec_public_key pk;
	unsigned char buf[BR_EC_KBUF_PUB_MAX_SIZE];
	struct dnskey *k;

	switch (sk->algorithm) {
	case ALGORITHM_ECDSAP256SHA256:
		if (br_ec_compute_pub(br_ec_get_default(), &pk, buf, &sk->ec) != 65)
			errx(1, "unexpected public key size");
		if (!(k = malloc(sizeof(*k) + 64)))
			err(1, "malloc");
		memcpy(k->data, buf + 1, 64);
		break;
	default:
		errx(1, "unsupported algorithm %s", algorithm_names[sk->algorithm]);
	}
	k->flags = flags;
	k->algorithm = sk->algorithm;
	k->protocol = 3;
	return k;
}

void
dnskey_hash(const struct dnskey *k, const br_hash_class **hc)
{
	(*hc)->update(hc, &(uint16_t){htons(k->flags)}, 2);
	(*hc)->update(hc, &k->protocol, 1);
	(*hc)->update(hc, &k->algorithm, 1);
	(*hc)->update(hc, &k->data, 64);
}

unsigned
dnskey_tag(const struct dnskey *k)
{
	unsigned long x;
	const unsigned char *p;
	size_t len;

	x = k->flags + (k->protocol << 8) + k->algorithm;
	switch (k->algorithm) {
	case ALGORITHM_ECDSAP256SHA256: len = 64; break;
	default:
		errx(1, "unsupported algorithm %d", k->algorithm);
	}
	for (p = k->data; len != 0; p += 2, len -= 2)
		x += (unsigned long)p[0] << 8 | p[1];
	return (x + (x >> 16)) & 0xffff;
}

static struct key *
key_new_ec(const br_ec_private_key *ec, int algorithm)
{
	struct key *k;

	if (!(k = malloc(sizeof(*k) + ec->xlen)))
		err(1, "malloc");
	k->ec = *ec;
	k->ec.x = k->data;
	memcpy(k->data, ec->x, ec->xlen);
	switch (k->ec.curve) {
	case BR_EC_secp256r1: k->algorithm = ALGORITHM_ECDSAP256SHA256; break;
	default:
		errx(1, "unsupported curve %d", k->ec.curve);
	}
	if (algorithm != -1 && algorithm != k->algorithm)
		errx(1, "key is incompatible with algorithm %s", algorithm_names[algorithm]);
	return k;
}

static void
key_decode(void *ctx, const void *buf, size_t len)
{
	br_skey_decoder_push(ctx, buf, len);
}

struct key *
key_new_from_file(const char *name)
{
	br_pem_decoder_context pc;
	br_skey_decoder_context kc;
	char buf[BUFSIZ], *p;
	size_t len = 0, n;
	int done = 0, algorithm = -1;
	FILE *f;

	if ((p = strchr(name, ':')) && !strchr(name, '/')) {
		*p = '\0';
		algorithm = algorithm_from_string(name);
		name = p + 1;
	}
	f = fopen(name, "r");
	if (!f)
		err(1, "open %s", name);
	br_pem_decoder_init(&pc);
	for (;;) {
		if (len == 0) {
			if (done)
				errx(1, "secret key PEM is truncated");
			len = fread(buf, 1, sizeof(buf), f);
			done = len != sizeof(buf);
			if (done) {
				if (ferror(f))
					err(1, "read %s", name);
				fclose(f);
			}
			p = buf;
		}
		n = br_pem_decoder_push(&pc, p, len);
		p += n;
		len -= n;
		switch (br_pem_decoder_event(&pc)) {
		case BR_PEM_BEGIN_OBJ:
			br_skey_decoder_init(&kc);
			br_pem_decoder_setdest(&pc, key_decode, &kc);
			break;
		case BR_PEM_END_OBJ:
			switch (br_skey_decoder_key_type(&kc)) {
			case BR_KEYTYPE_RSA:
				errx(1, "RSA key is not yet supported");
			case BR_KEYTYPE_EC:
				return key_new_ec(br_skey_decoder_get_ec(&kc), algorithm);
			default:
				errx(1, "failed to decode secret key: error %d",
				     br_skey_decoder_last_error(&kc));
			}
			break;
		case BR_PEM_ERROR:
			errx(1, "failed to decode secret key PEM");
		}
	}
}
