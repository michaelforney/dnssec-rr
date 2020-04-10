#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <err.h>
#include "dnssec.h"

static void
usage(void)
{
	fprintf(stderr, "usage: dsfromkey [-d digest] [-t ttl] [-c class] domain [algorithm:]keyfile\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	int digest = DIGEST_SHA256, class = CLASS_IN, c;
	unsigned long ttl = 86400;

	while ((c = getopt(argc, argv, "d:t:c:")) != -1) {
		switch (c) {
		char *end;
		case 'd':
			digest = digest_from_string(optarg);
			break;
		case 't':
			ttl = strtoul(optarg, &end, 10);
			if (*end)
				errx(1, "invalid TTL");
			break;
		case 'c':
			class = class_from_string(optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
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

	hc.vtable->init(&hc.vtable);
	dname_hash(argv[0], &hc.vtable);
	hc.vtable->update(&hc.vtable, &(uint16_t){htons(pk->flags)}, 2);
	hc.vtable->update(&hc.vtable, &(uint8_t){pk->protocol}, 1);
	hc.vtable->update(&hc.vtable, &(uint8_t){pk->algorithm}, 1);
	hc.vtable->update(&hc.vtable, pk->data, pk->data_length);
	unsigned char hash[64];
	size_t hash_len = hc.vtable->desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK;
	hc.vtable->out(&hc.vtable, hash);

	printf("%s\t%lu\t%s\tDS\t%u %d %d ",
	       argv[0], ttl, class_to_string(class), dnskey_tag(pk), pk->algorithm, digest);
	for (size_t i = 0; i < hash_len; ++i)
		printf("%02x", hash[i]);
	putchar('\n');

	fflush(stdout);
	if (ferror(stdout))
		errx(1, "write failed");
}