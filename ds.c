#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <err.h>
#include "dnssec.h"
#include "arg.h"

static void
usage(void)
{
	fprintf(stderr, "usage: dsfromkey [-d digest] [-t ttl] [-c class] domain [algorithm:]keyfile\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	int digest = DIGEST_SHA256, class = CLASS_IN;
	unsigned long ttl = 0;
	char *end;

	ARGBEGIN {
	case 'd':
		digest = digest_from_string(EARGF(usage()));
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

	br_hash_compat_context hc;
	switch (digest) {
	case DIGEST_SHA1:   hc.vtable = &br_sha1_vtable;   break;
	case DIGEST_SHA256: hc.vtable = &br_sha256_vtable; break;
	case DIGEST_SHA384: hc.vtable = &br_sha384_vtable; break;
	default:
		errx(1, "unsupported digest %d", digest);
	}

	struct key *sk = key_new_from_file(argv[1]);
	struct dnskey *pk = dnskey_new(DNSKEY_ZONE | DNSKEY_SEP, sk);

	unsigned char dname[DNAME_MAX];
	size_t dname_len = dname_parse(argv[0], &end, dname, NULL, 0);
	if (dname_len == 0 || *end)
		errx(1, "invalid domain name '%s'", argv[0]);

	hc.vtable->init(&hc.vtable);
	hc.vtable->update(&hc.vtable, dname, dname_len);
	hc.vtable->update(&hc.vtable, &(uint16_t){htons(pk->flags)}, 2);
	hc.vtable->update(&hc.vtable, &(uint8_t){pk->protocol}, 1);
	hc.vtable->update(&hc.vtable, &(uint8_t){pk->algorithm}, 1);
	hc.vtable->update(&hc.vtable, pk->data, pk->data_len);
	unsigned char hash[64];
	size_t hash_len = hc.vtable->desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK;
	hc.vtable->out(&hc.vtable, hash);

	fputs(argv[0], stdout);
	if (ttl)
		printf("\t%lu", ttl);
	printf("\t%s\tDS\t%u %d %d ", class_to_string(class), dnskey_tag(pk), pk->algorithm, digest);
	for (size_t i = 0; i < hash_len; ++i)
		printf("%02x", hash[i]);
	putchar('\n');

	fflush(stdout);
	if (ferror(stdout))
		errx(1, "write failed");
}
