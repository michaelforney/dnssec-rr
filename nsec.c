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
	const char *name = "<stdin>";
	FILE *file = stdin;

	if (argc > 2)
		usage();
	if (argc == 2) {
		name = argv[1];
		if (!(file = fopen(name, "r")))
			err(1, "open %s", name);
	}

	struct zone *z = zone_new_from_file(name, file);
	for (size_t i = 0, j = 0; i < z->rr_len; i = j) {
		unsigned char m[32] = {0}, t;
		m[TYPE_NSEC / 8] |= 0x80 >> (TYPE_NSEC % 8);
		m[TYPE_RRSIG / 8] |= 0x80 >> (TYPE_RRSIG % 8);
		do {
			if ((t = z->rr[j]->type) > 255)
				errx(1, "record types above 255 are not supported");
			m[t / 8] |= 0x80 >> (t % 8);
		} while (++j < z->rr_len && dname_compare(z->rr[i]->name, z->rr[j]->name) == 0);

		dname_print(z->rr[i]->name);
		printf("\t%lu\t%s\tNSEC\t", z->soa.minimum_ttl, class_to_string(z->rr[i]->class));
		dname_print(z->rr[j % z->rr_len]->name);
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
