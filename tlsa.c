#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <err.h>
#include "dnssec.h"
#include "arg.h"

#define LEN(a) (sizeof(a) / sizeof((a)[0]))

enum {
	SELECTOR_CERT,
	SELECTOR_PUBKEY,
};

enum {
	MATCH_FULL,
	MATCH_SHA256,
	MATCH_SHA512,
};

struct asn1 {
	int tag;
	size_t len;
};

static br_hash_compat_context hc;
static br_x509_certificate cert;
static int selector = SELECTOR_PUBKEY;

static void
usage(void)
{
	fprintf(stderr, "usage: dsfromkey [-C] [-m match] [-u usage] [-t ttl] [-c class] domain certfile\n");
	exit(2);
}

static size_t
encode_len(size_t len, unsigned char *buf)
{
	size_t x;
	int n, i;

	if (len < 0x80) {
		if (buf)
			buf[0] = len;
		return 1;
	}
	for (x = len, n = 0; x; x >>= 8, ++n)
		;
	if (buf) {
		*buf++ = 0x80 | n;
		for (i = n - 1; i >= 0; --i)
			*buf++ = len >> (i << 3);
	}
	return 1 + n;
}

static size_t
encode(struct asn1 *v, unsigned char *buf)
{
	unsigned char *pos;

	if (!buf)
		return 1 + encode_len(v->len, NULL) + v->len;
	pos = buf;
	*pos++ = v->tag;
	pos += encode_len(v->len, pos);
	return pos - buf;
}

static size_t
encode_uint(const unsigned char *num, size_t len, unsigned char *buf)
{
	int pad = len == 0 || *num & 0x80;
	struct asn1 val = {0x02, len + pad};
	unsigned char *pos;

	if (!buf)
		return encode(&val, NULL);
	pos = buf;
	pos += encode(&val, pos);
	if (pad)
		*pos++ = 0;
	memcpy(pos, num, len);
	pos += len;
	return pos - buf;
}

static size_t
encode_rsa(const br_rsa_public_key *pk, unsigned char *buf)
{
	static const unsigned char alg[] = {
		0x30, 0x0d,
		/* OID 1.2.840.113549.1.1.1 - rsaEncryption */
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
		/* NULL parameters */
		0x05, 0x00,
	};
	struct asn1 val = {0x30}, key = {0x03}, rsa = {0x30};
	size_t len;

	rsa.len = encode_uint(pk->n, pk->nlen, NULL) + encode_uint(pk->e, pk->elen, NULL);
	key.len = 1 + encode(&rsa, NULL);
	val.len = sizeof(alg) + encode(&key, NULL);
	len = encode(&val, NULL);
	if (buf) {
		unsigned char *pos = buf;
		pos += encode(&val, pos);
		memcpy(pos, alg, sizeof(alg));
		pos += sizeof(alg);
		pos += encode(&key, pos);
		*pos++ = 0;
		pos += encode(&rsa, pos);
		pos += encode_uint(pk->n, pk->nlen, pos);
		pos += encode_uint(pk->e, pk->elen, pos);
		assert(pos - buf == len);
	}
	return len;
}

static size_t
encode_ec(const br_ec_public_key *pk, unsigned char *buf)
{
	static const unsigned char oid[] = {
		/* OID 1.2.840.10045.2.1 - id-ecPublicKey */
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	};
	static const unsigned char oid_secp256r1[] = {
		/* OID 1.2.840.10045.3.1.7 - secp256r1 */
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	};
	static const unsigned char oid_secp384r1[] = {
		/* OID 1.3.132.0.34 - secp384r1 */
		0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
	};
	static const unsigned char oid_secp521r1[] = {
		/* OID 1.3.132.0.34 - secp521r1 */
		0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
	};
	struct asn1 val = {0x30}, alg = {0x30}, key = {0x03};
	const unsigned char *curve;
	size_t len;

	switch (pk->curve) {
	case BR_EC_secp256r1: curve = oid_secp256r1; break;
	case BR_EC_secp384r1: curve = oid_secp384r1; break;
	case BR_EC_secp521r1: curve = oid_secp521r1; break;
	default: errx(1, "unsupported EC curev");
	}
	alg.len = sizeof(oid) + 2 + curve[1];
	key.len = 1 + pk->qlen;
	val.len = encode(&alg, NULL) + encode(&key, NULL);
	len = encode(&val, NULL);
	if (buf) {
		unsigned char *pos = buf;
		pos += encode(&val, pos);
		pos += encode(&alg, pos);
		memcpy(pos, oid, sizeof(oid));
		pos += sizeof(oid);
		memcpy(pos, curve, 2 + curve[1]);
		pos += 2 + curve[1];
		pos += encode(&key, pos);
		*pos++ = 0;
		memcpy(pos, pk->q, pk->qlen);
		pos += pk->qlen;
		assert(pos - buf == len);
	}
	return len;
}

static size_t
encode_pkey(const br_x509_pkey *pk, unsigned char *buf)
{
	switch (pk->key_type) {
	case BR_KEYTYPE_RSA: return encode_rsa(&pk->key.rsa, buf);
	case BR_KEYTYPE_EC: return encode_ec(&pk->key.ec, buf);
	}
	errx(1, "unsupported public key type");
}

static const char *usage_names[] = {
	"pkix-ta",
	"pkix-ee",
	"dane-ta",
	"dane-ee",
};

static const char *selector_names[] = {
	"cert",
	"pubkey",
};

static const char *match_names[] = {
	"exact",
	"sha256",
	"sha512",
};

static int
from_string(const char *s, const char *desc, const char *const names[], size_t names_len)
{
	for (size_t i = 0; i < names_len; ++i) {
		if (strcasecmp(names[i], s) == 0 || (s[0] == '0' + i && s[1] == 0))
			return i;
	}
	errx(1, "unknown %s '%s'", desc, s);
}

static void
append_x509(void *ctx, const void *buf, size_t len)
{
	if (selector == SELECTOR_CERT) {
		if (hc.vtable) {
			hc.vtable->update(&hc.vtable, buf, len);
		} else {
			size_t new_len = cert.data_len + len;

			cert.data = realloc(cert.data, new_len);
			memcpy(cert.data + cert.data_len, buf, len);
			cert.data_len = new_len;
		}
	}
	br_x509_decoder_push(ctx, buf, len);
}

int
main(int argc, char *argv[])
{
	int class = CLASS_IN, usage_type = 3, match = MATCH_SHA256;
	unsigned long ttl = 0;
	FILE *f;
	br_pem_decoder_context pc;
	br_x509_decoder_context xc;
	const br_x509_pkey *pk = NULL;
	char buf[8192], *pos, *end;
	unsigned char hash[64], *data;
	size_t len = 0, n, data_len;
	int done = 0, found = 0, errcode;

	ARGBEGIN {
	case 's':
		selector = from_string(EARGF(usage()), "selector", selector_names, LEN(selector_names));
		break;
	case 'm':
		match = from_string(EARGF(usage()), "matching type", match_names, LEN(match_names));
		break;
	case 'u':
		usage_type = from_string(EARGF(usage()), "usage type", usage_names, LEN(usage_names));
		break;
	case 't':
		ttl = strtoul(EARGF(usage()), &end, 10);
		if (*end)
			errx(1, "invalid TTL");
		break;
	case 'c':
		class = class_from_string(EARGF(usage()));
		break;
	default:
		usage();
	} ARGEND
	if (argc != 2)
		usage();

	f = fopen(argv[1], "r");
	if (!f)
		err(1, "open %s", argv[1]);
	switch (match) {
	case MATCH_SHA256: hc.vtable = &br_sha256_vtable; break;
	case MATCH_SHA512: hc.vtable = &br_sha512_vtable; break;
	}
	if (hc.vtable)
		hc.vtable->init(&hc.vtable);
	br_pem_decoder_init(&pc);
	br_x509_decoder_init(&xc, NULL, NULL);
	while (!pk) {
		if (len == 0) {
			if (done)
				errx(1, "invalid certificate PEM");
			len = fread(buf, 1, sizeof(buf), f);
			done = len != sizeof(buf);
			if (done) {
				if (ferror(f))
					err(1, "read %s", argv[0]);
			}
			pos = buf;
		}
		n = br_pem_decoder_push(&pc, pos, len);
		pos += n;
		len -= n;
		switch (br_pem_decoder_event(&pc)) {
		case BR_PEM_BEGIN_OBJ:
			if (strcmp(br_pem_decoder_name(&pc), "CERTIFICATE") == 0) {
				br_pem_decoder_setdest(&pc, append_x509, &xc);
				found = 1;
			}
			break;
		case BR_PEM_END_OBJ:
			if (found) {
				errcode = br_x509_decoder_last_error(&xc);
				if (errcode)
					errx(1, "X.509 decoding error %d", err);
				pk = br_x509_decoder_get_pkey(&xc);
			}
			break;
		case BR_PEM_ERROR:
			errx(1, "failed to decode certificate PEM");
		}
	}

	switch (selector) {
	case SELECTOR_CERT:
		data = cert.data;
		data_len = cert.data_len;
		break;
	case SELECTOR_PUBKEY:
		if (!(data = malloc(encode_pkey(pk, NULL))))
			err(1, "malloc");
		data_len = encode_pkey(pk, data);
		if (hc.vtable)
			hc.vtable->update(&hc.vtable, data, data_len);
		break;
	}

	fputs(argv[0], stdout);
	if (ttl)
		printf("\t%lu", ttl);
	printf("\t%s\tTLSA\t%d %d %d ", class_to_string(class), usage_type, selector, match);
	if (hc.vtable) {
		hc.vtable->out(&hc.vtable, hash);
		data = hash;
		data_len = hc.vtable->desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK;
	}
	for (size_t i = 0; i < data_len; ++i)
		printf("%02x", data[i]);
	putchar('\n');

	fflush(stdout);
	if (ferror(stdout))
		errx(1, "write failed");
}
