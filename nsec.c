#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include "dnssec.h"

static void
usage(void)
{
	fprintf(stderr, "usage: nsec [zone]\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	if (argc > 0)
		--argc, ++argv;
	if (argc > 1)
		usage();

	struct zone z;
	char errmsg[256];
	if (zone_parse(&z, argv[0], errmsg, sizeof(errmsg)) != 0) {
		fprintf(stderr, "%s\n", errmsg);
		errx(1, "zone parse failed");
	}
	for (size_t i = 0, j = 0; i < z.rr_len; i = j) {
		unsigned char m[32] = {0}, t;
		m[TYPE_NSEC / 8] |= 0x80 >> (TYPE_NSEC % 8);
		m[TYPE_RRSIG / 8] |= 0x80 >> (TYPE_RRSIG % 8);
		do {
			if ((t = z.rr[j]->type) > 255)
				errx(1, "record types above 255 are not supported");
			m[t / 8] |= 0x80 >> (t % 8);
		} while (++j < z.rr_len && dname_compare(z.rr[i]->name, z.rr[j]->name) == 0);

		dname_print(z.rr[i]->name);
		printf("\t%lu\t%s\tNSEC\t", z.minimum_ttl, class_to_string(z.rr[i]->class));
		dname_print(z.rr[j % z.rr_len]->name);
		for (int t = 0; t <= 255; ++t) {
			if (m[t / 8] & 0x80 >> t % 8)
				printf(" %s", type_to_string(t));
		}
		putchar('\n');
	}

	fflush(stdout);
	if (ferror(stdout))
		errx(1, "write failed");
}
