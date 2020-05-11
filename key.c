#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <bearssl.h>
#include "dnssec.h"

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
		errx(1, "key is incompatible with algorithm %s", algorithm_to_string(algorithm));
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
		errx(1, "key is incompatible with algorithm %s", algorithm_to_string(algorithm));
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
