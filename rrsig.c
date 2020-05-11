#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <err.h>
#include "dnssec.h"

static void
usage(void)
{
	fprintf(stderr, "usage: rrsig [-kz] [-s start] [-e end] [algorithm:]keyfile [zonefile]\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	const char *name = "<stdin>";
	FILE *file = stdin;
	int kflag = 0, zflag = 0, c;
	unsigned long start_time = 0, end_time = 0;

	while ((c = getopt(argc, argv, "s:e:kz")) != -1) {
		switch (c) {
		char *end;
		case 's':
			start_time = strtoul(optarg, &end, 0);
			if (*end)
				usage();
			break;
		case 'e':
			break;
		case 'k':
			kflag = 1;
			break;
		case 'z':
			zflag = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1 && argc != 2)
		usage();
	if (argc == 2) {
		name = argv[1];
		if (!(file = fopen(name, "r")))
			err(1, "open %s", name);
	}

	if (!kflag && !zflag) {
		kflag = 1;
		zflag = 1;
	}
	if (!start_time && (start_time = time(NULL)) == -1)
		err(1, "time");
	if (!end_time)
		end_time = start_time + 30 * 86400;

	struct zone *z = zone_new_from_file(name, file);
	struct key *sk = key_new_from_file(argv[0]);
	struct dnskey *pk = dnskey_new(DNSKEY_ZONE | (kflag ? DNSKEY_SEP : 0), sk);

	br_hash_compat_context hc;
	const br_ec_impl *ec = br_ec_get_default();
	br_ecdsa_sign ecdsa_sign = br_ecdsa_sign_raw_get_default();
	br_rsa_pkcs1_sign rsa_sign = br_rsa_pkcs1_sign_get_default();
	const unsigned char *hash_oid = NULL;
	switch (sk->algorithm) {
	case ALGORITHM_ECDSAP256SHA256:
		hc.vtable = &br_sha256_vtable;
		break;
	case ALGORITHM_ECDSAP384SHA384:
		hc.vtable = &br_sha384_vtable;
		break;
	case ALGORITHM_RSASHA1:
		hc.vtable = &br_sha1_vtable;
		hash_oid = BR_HASH_OID_SHA1;
		break;
	case ALGORITHM_RSASHA256:
		hc.vtable = &br_sha256_vtable;
		hash_oid = BR_HASH_OID_SHA256;
		break;
	case ALGORITHM_RSASHA512:
		hc.vtable = &br_sha512_vtable;
		hash_oid = BR_HASH_OID_SHA512;
		break;
	default:
		errx(1, "unsupported algorithm %d", sk->algorithm);
	}

	char start[32], end[32];
	struct tm *tm;
	if (!(tm = gmtime(&(time_t){start_time})))
		err(1, "gmtime");
	strftime(start, sizeof(start), "%Y%m%d%H%M%S", tm);
	if (!(tm = gmtime(&(time_t){end_time})))
		err(1, "gmtime");
	strftime(end, sizeof(end), "%Y%m%d%H%M%S", tm);

	for (size_t i = 0, j = 0; i < z->rr_len; i = j) {
		if ((!kflag && z->rr[i]->type == TYPE_DNSKEY) || (!zflag && z->rr[i]->type != TYPE_DNSKEY)) {
			j = i + 1;
			continue;
		}

		struct rr *rr = z->rr[i];
		int labels = dname_labels(rr->name);
		unsigned tag = dnskey_tag(pk);
		dname_print(rr->name);
		printf("\t%lu\t%s\tRRSIG\t%s %d %d %lu %s %s %u ",
		       rr->ttl, class_to_string(rr->class), type_to_string(rr->type),
		       sk->algorithm, labels, rr->ttl, end, start, tag);
		dname_print(z->rr[0]->name);
		putchar(' ');
		hc.vtable->init(&hc.vtable);
		hc.vtable->update(&hc.vtable, &(uint16_t){htons(rr->type)}, 2);
		hc.vtable->update(&hc.vtable, &(uint8_t){sk->algorithm}, 1);
		hc.vtable->update(&hc.vtable, &(uint8_t){labels}, 1);
		hc.vtable->update(&hc.vtable, &(uint32_t){htonl(rr->ttl)}, 4);
		hc.vtable->update(&hc.vtable, &(uint32_t){htonl(end_time)}, 4);
		hc.vtable->update(&hc.vtable, &(uint32_t){htonl(start_time)}, 4);
		hc.vtable->update(&hc.vtable, &(uint16_t){htons(tag)}, 2);
		hc.vtable->update(&hc.vtable, z->rr[0]->name, z->rr[0]->name_len);
		do {
			hc.vtable->update(&hc.vtable, z->rr[j]->name, z->rr[j]->name_len);
			hc.vtable->update(&hc.vtable, &(uint16_t){htons(z->rr[j]->type)}, 2);
			hc.vtable->update(&hc.vtable, &(uint16_t){htons(z->rr[j]->class)}, 2);
			hc.vtable->update(&hc.vtable, &(uint32_t){htonl(z->rr[j]->ttl)}, 4);
			hc.vtable->update(&hc.vtable, &(uint16_t){htons(z->rr[j]->rdata_len)}, 2);
			hc.vtable->update(&hc.vtable, z->rr[j]->rdata, z->rr[j]->rdata_len);
		} while (++j < z->rr_len && dname_compare(rr->name, z->rr[j]->name) == 0 && rr->type == z->rr[j]->type);

		unsigned char hash[64];
		size_t hash_len = hc.vtable->desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK;
		hc.vtable->out(&hc.vtable, hash);

		unsigned char sig[4096];
		size_t sig_len;
		switch (sk->algorithm) {
		case ALGORITHM_ECDSAP256SHA256:
		case ALGORITHM_ECDSAP384SHA384:
			sig_len = ecdsa_sign(ec, hc.vtable, hash, &sk->ec, sig);
			if (sig_len == 0)
				errx(1, "failed to sign RRset");
			break;
		case ALGORITHM_RSASHA1:
		case ALGORITHM_RSASHA256:
		case ALGORITHM_RSASHA512:
			if (rsa_sign(hash_oid, hash, hash_len, &sk->rsa, sig) != 1)
				errx(1, "failed to sign RRset");
			sig_len = (sk->rsa.n_bitlen + 7) / 8;
			break;
		default:
			errx(1, "unsupported algorithm %d", sk->algorithm);
		}
		char sig_b64[(sizeof(sig) + 2) / 3 * 4 + 1];
		base64_encode(sig_b64, sig, sig_len);
		puts(sig_b64);
	}

	fflush(stdout);
	if (ferror(stdout))
		errx(1, "write failed");
}
