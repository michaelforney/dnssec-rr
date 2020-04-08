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
	[TYPE_DS]     = "DS",
	[TYPE_RRSIG]  = "RRSIG",
	[TYPE_NSEC]   = "NSEC",
	[TYPE_DNSKEY] = "DNSKEY",
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
type_to_string(int class)
{
	return type_names[class];
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
	case ALGORITHM_RSASHA1:
	case ALGORITHM_RSASHA256:
	case ALGORITHM_RSASHA512:;
		uint32_t e = br_rsa_compute_pubexp_get_default()(&sk->rsa);
		if (!e)
			errx(1, "failed to compute public exponent of RSA key");
		printf("e is %u\n", e);
		size_t nlen = br_rsa_compute_modulus_get_default()(NULL, &sk->rsa);
		if (!nlen)
			errx(1, "failed to compute public modulus of RSA key");
		if (!(k = malloc(sizeof(*k) + 5 + nlen)))
			err(1, "malloc");
		/* leading zeros in exponent are prohibited */
		for (k->data[0] = 4; !(e & 0xff000000); --k->data[0])
			e <<= 8;
		k->data_length = 1 + k->data[0] + nlen;
		memcpy(k->data + 1, &(uint32_t){htonl(e)}, k->data[0]);
		br_rsa_compute_modulus_get_default()(k->data + 1 + k->data[0], &sk->rsa);
		break;
	case ALGORITHM_ECDSAP256SHA256:
		if (br_ec_compute_pub(br_ec_get_default(), &pk, buf, &sk->ec) != 65)
			errx(1, "unexpected public key size");
		if (!(k = malloc(sizeof(*k) + 64)))
			err(1, "malloc");
		k->data_length = 64;
		memcpy(k->data, buf + 1, 64);
		break;
	case ALGORITHM_ECDSAP384SHA384:
		if (br_ec_compute_pub(br_ec_get_default(), &pk, buf, &sk->ec) != 97)
			errx(1, "unexpected public key size");
		if (!(k = malloc(sizeof(*k) + 96)))
			err(1, "malloc");
		k->data_length = 96;
		memcpy(k->data, buf + 1, 96);
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
	(*hc)->update(hc, &k->data, k->data_length);
}

unsigned
dnskey_tag(const struct dnskey *k)
{
	unsigned long x;
	const unsigned char *p;
	size_t i;

	x = k->flags + (k->protocol << 8) + k->algorithm;
	for (i = 0, p = k->data; i < k->data_length; ++p, ++i)
		x += i & 1 ? *p : (unsigned long)*p << 8;
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
	case BR_EC_secp384r1: k->algorithm = ALGORITHM_ECDSAP384SHA384; break;
	default:
		errx(1, "unsupported curve %d", k->ec.curve);
	}
	if (algorithm != -1 && algorithm != k->algorithm)
		errx(1, "key is incompatible with algorithm %s", algorithm_names[algorithm]);
	return k;
}

static struct key *
key_new_rsa(const br_rsa_private_key *rsa, int algorithm)
{
	struct key *k;

	if (!(k = malloc(sizeof(*k) + rsa->plen + rsa->qlen + rsa->dplen + rsa->dqlen + rsa->iqlen)))
		err(1, "malloc");
	k->rsa = *rsa;
	k->rsa.p = k->data;
	k->rsa.q = k->rsa.p + k->rsa.plen;
	k->rsa.dp = k->rsa.q + k->rsa.qlen;
	k->rsa.dq = k->rsa.dp + k->rsa.dplen;
	k->rsa.iq = k->rsa.dq + k->rsa.dqlen;
	memcpy(k->rsa.p, rsa->p, rsa->plen);
	memcpy(k->rsa.q, rsa->q, rsa->qlen);
	memcpy(k->rsa.dp, rsa->dp, rsa->dplen);
	memcpy(k->rsa.dq, rsa->dq, rsa->dqlen);
	memcpy(k->rsa.iq, rsa->iq, rsa->iqlen);
	switch (algorithm) {
	case ALGORITHM_RSASHA1:
	case ALGORITHM_RSASHA256:
	case ALGORITHM_RSASHA512:
		k->algorithm = algorithm;
		break;
	case -1:
		k->algorithm = ALGORITHM_RSASHA256;
		break;
	default:
		errx(1, "key is incompatible with algorithm %s", algorithm_names[algorithm]);
	}
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
				return key_new_rsa(br_skey_decoder_get_rsa(&kc), algorithm);
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
