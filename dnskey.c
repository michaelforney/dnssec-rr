#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include "dnssec.h"

static void
usage(void)
{
	fprintf(stderr, "usage: dnskey [-k] [-t ttl] [-c class] domain [algorithm:]keyfile\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	int class = CLASS_IN, flags = DNSKEY_ZONE, c;
	unsigned long ttl = 86400;

	while ((c = getopt(argc, argv, "kt:c:")) != -1) {
		switch (c) {
		char *end;
		case 'k':
			flags |= DNSKEY_SEP;
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

	struct key *sk = key_new_from_file(argv[1]);
	struct dnskey *pk = dnskey_new(flags, sk);
	printf("%s\t%lu\t%s\tDNSKEY\t%u %d %d ", argv[0], ttl, class_to_string(class), pk->flags, pk->protocol, pk->algorithm);
	for (size_t i = 0; i < pk->data_len; i += 300) {
		char data[401];
		base64_encode(data, pk->data + i, i + 300 < pk->data_len ? 300 : pk->data_len - i);
		fputs(data, stdout);
	}
	putchar('\n');

	fflush(stdout);
	if (ferror(stdout))
		errx(1, "write failed");
}
