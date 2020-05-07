#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <err.h>
#include "dnssec.h"

static int
rr_compare(const void *p1, const void *p2)
{
	const struct rr *rr1 = *(const struct rr **)p1, *rr2 = *(const struct rr **)p2;
	int r;

	if ((r = dname_compare(rr1->name, rr2->name)))
		return r;
	/* sort SOA before other record types so that it is always first in the zone */
	if (rr1->type != rr2->type)
		return rr1->type == TYPE_SOA ? -1 : rr2->type == TYPE_SOA ? 1 : rr1->type - rr2->type;
	if (rr1->class != rr2->class)
		return rr1->class - rr2->class;
	size_t len = rr1->rdata_len < rr2->rdata_len ? rr1->rdata_len : rr2->rdata_len;
	if ((r = memcmp(rr1->rdata, rr2->rdata, len)) != 0 || rr1->rdata_len == rr2->rdata_len)
		return r;
	return len == rr1->rdata_len ? -1 : 1;
}

static void
zone_add(struct zone *z, struct rr *rr)
{
	struct rr **rrs;

	if (!(z->rr_len & (z->rr_len - 1))) {
		if (!(rrs = realloc(z->rr, (z->rr_len ? z->rr_len * 2 : 1) * sizeof(rr))))
			err(1, "realloc");
		z->rr = rrs;
	}
	z->rr[z->rr_len++] = rr;
}

static struct rr *
rr_new(unsigned char *name, size_t name_len, int type, int class, unsigned long ttl, size_t rdata_len)
{
	struct rr *rr;

	if (!(rr = malloc(sizeof(*rr) + rdata_len)))
		err(1, "malloc");
	memcpy(rr->name, name, name_len);
	rr->name_len = name_len;
	rr->type = type;
	rr->class = class;
	rr->ttl = ttl;
	rr->rdata_len = rdata_len;
	return rr;
}

struct zone *
zone_new_from_file(const char *path, FILE *file)
{
	struct zone *z;
	char *buf = NULL;
	size_t len = 0;

	if (!(z = malloc(sizeof(*z))))
		err(1, "malloc");
	z->rr = NULL;
	z->rr_len = 0;
	for (;;) {
		ssize_t n;
		if ((n = getline(&buf, &len, file)) < 0) {
			if (ferror(file))
				err(1, "read %s", path);
			break;
		}
		if (buf[n - 1] == '\n')
			buf[n - 1] = '\0';
		char *tok;
		if (!(tok = strtok(buf, " \t")))
			continue;
		unsigned char name[DNAME_MAX];
		size_t name_len = dname_parse(tok, name, NULL, 0);
		if (name_len == 0)
			errx(1, "invalid RR: invalid name");
		if (!(tok = strtok(NULL, " \t")))
			errx(1, "invalid RR: expected TTL");
		unsigned long ttl = strtoul(tok, &tok, 10);
		if (*tok)
			errx(1, "invalid RR: invalid TTL");
		if (!(tok = strtok(NULL, " \t")))
			errx(1, "invalid RR: expected class");
		int class = class_from_string(tok);
		if (!(tok = strtok(NULL, " \t")))
			errx(1, "invalid RR: expected type");
		int type = type_from_string(tok);
		struct rr *rr;
		if ((type == TYPE_SOA) != (z->rr_len == 0))
			errx(1, "exactly one SOA record must be present at start of zone");
		switch (type) {
		unsigned char *p;
		case TYPE_A:
			rr = rr_new(name, name_len, type, class, ttl, 4);
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid A: expected IP address");
			if (inet_pton(AF_INET, tok, rr->rdata) != 1)
				err(1, "invalid A: inet_pton");
			break;
		case TYPE_NS:
		case TYPE_CNAME: {
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid %s: expected name server", type_to_string(type));
			unsigned char dname[DNAME_MAX];
			size_t len = dname_parse(tok, dname, NULL, 0);
			if (len == 0)
				errx(1, "invalid %s: invalid name server", type_to_string(type));
			rr = rr_new(name, name_len, type, class, ttl, len);
			memcpy(rr->rdata, dname, len);
			break;
		}
		case TYPE_SOA: {
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SOA: expected name server");
			unsigned char mname[DNAME_MAX];
			size_t mname_len = dname_parse(tok, mname, NULL, 0);
			if (mname_len == 0)
				errx(1, "invalid SOA: invalid name server");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SOA: expected owner mailbox");
			unsigned char rname[DNAME_MAX];
			size_t rname_len = dname_parse(tok, rname, NULL, 0);
			if (rname_len == 0)
				errx(1, "invalid SOA: invalid owner mailbax");

			rr = rr_new(name, name_len, TYPE_SOA, class, ttl, mname_len + rname_len + 20);
			p = rr->rdata;
			memcpy(p, mname, mname_len);
			p += mname_len;
			memcpy(p, rname, rname_len);
			p += rname_len;

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SOA: expected serial number");
			memcpy(p, &(uint32_t){htonl(strtoul(tok, &tok, 10))}, 4);
			if (*tok)
				errx(1, "invalid SOA: invalid serial number");
			p += 4;

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SOA: expected refresh interval");
			memcpy(p, &(uint32_t){htonl(strtoul(tok, &tok, 10))}, 4);
			if (*tok)
				errx(1, "invalid SOA: invalid refresh interval");
			p += 4;

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SOA: expected retry interval");
			memcpy(p, &(uint32_t){htonl(strtoul(tok, &tok, 10))}, 4);
			if (*tok)
				errx(1, "invalid SOA: invalid retry interval");
			p += 4;

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SOA: expected expire interval");
			memcpy(p, &(uint32_t){htonl(strtoul(tok, &tok, 10))}, 4);
			if (*tok)
				errx(1, "invalid SOA: invalid expire interval");
			p += 4;

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SOA: expected minimum TTL");
			z->soa.minimum_ttl = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid SOA: invalid minimum TTL");
			memcpy(p, &(uint32_t){htonl(z->soa.minimum_ttl)}, 4);
			break;
		}
		case TYPE_MX: {
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid MX: expected priority");
			unsigned priority = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid MX: invalid priority");
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid MX: expected domain name");
			unsigned char dname[DNAME_MAX];
			size_t dname_len = dname_parse(tok, dname, NULL, 0);
			if (dname_len == 0)
				errx(1, "invalid MX: invalid domain name");
			rr = rr_new(name, name_len, type, class, ttl, 2 + dname_len);
			memcpy(rr->rdata, &(uint16_t){htons(priority)}, 2);
			memcpy(rr->rdata + 2, dname, dname_len);
			break;
		}
		case TYPE_AAAA:
			rr = rr_new(name, name_len, type, class, ttl, 16);
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid AAAA: expected IP address");
			if (inet_pton(AF_INET6, tok, rr->rdata) != 1)
				err(1, "invalid AAAA: inet_pton");
			break;
		case TYPE_SRV: {
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SRV: expected priority");
			unsigned priority = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid SRV: invalid priority");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SRV: expected weight");
			unsigned weight = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid SRV: invalid weight");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SRV: expected port");
			unsigned port = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid SRV: invalid port");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid SRV: expected domain name");
			unsigned char dname[DNAME_MAX];
			size_t dname_len = dname_parse(tok, dname, NULL, 0);
			if (dname_len == 0)
				errx(1, "invalid SRV: invalid domain name");
			rr = rr_new(name, name_len, type, class, ttl, 6 + dname_len);
			memcpy(rr->rdata, &(uint16_t){htons(priority)}, 2);
			memcpy(rr->rdata + 2, &(uint16_t){htons(weight)}, 2);
			memcpy(rr->rdata + 4, &(uint16_t){htons(port)}, 2);
			memcpy(rr->rdata + 6, dname, dname_len);
			break;
		}
		case TYPE_DNSKEY:
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid DNSKEY: expected flags");
			unsigned flags = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid DNSKEY: invalid flags");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid DNSKEY: expected protocol");
			int protocol = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid DNSKEY: invalid protocol");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid DNSKEY: expected algorithm");
			int algorithm = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid DNSKEY: invalid protocol");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid DNSKEY: expected public key");
			rr = rr_new(name, name_len, type, class, ttl, 4 + strlen(tok) * 3 / 4);
			memcpy(rr->rdata, &(uint16_t){htons(flags)}, 2);
			rr->rdata[2] = protocol;
			rr->rdata[3] = algorithm;
			rr->rdata_len = 4 + base64_decode(rr->rdata + 4, tok);
			break;
		case TYPE_NSEC: {
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid NSEC: expected next domain name");
			unsigned char dname[DNAME_MAX];
			size_t dname_len = dname_parse(tok, dname, NULL, 0);
			if (dname_len == 0)
				errx(1, "invalid NSEC: invalid next domain name");
			rr = rr_new(name, name_len, type, class, ttl, dname_len + 34);
			p = rr->rdata;
			memcpy(p, dname, dname_len);
			p += dname_len;
			memset(p, 0, 34);
			while ((tok = strtok(NULL, " \t"))) {
				if ((type = type_from_string(tok)) > 255)
					errx(1, "unsupported record type %s", tok);
				p[2 + type / 8] |= 0x80 >> type % 8;
				if (type / 8 + 1 > p[1])
					p[1] = type / 8 + 1;
			}
			rr->rdata_len -= 32 - p[1];
			break;
		}
		case TYPE_TLSA:
			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid TLSA: expected usage");
			int usage = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid SOA: invalid refresh interval");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid TLSA: expected selector");
			int selector = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid SOA: invalid selector");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid TLSA: expected match type");
			int match = strtoul(tok, &tok, 10);
			if (*tok)
				errx(1, "invalid SOA: invalid match type");

			if (!(tok = strtok(NULL, " \t")))
				errx(1, "invalid TLSA: expected certificate association data");
			rr = rr_new(name, name_len, type, class, ttl, 3 + strlen(tok) / 2);
			rr->rdata[0] = usage;
			rr->rdata[1] = selector;
			rr->rdata[2] = match;
			rr->rdata_len = 3 + base16_decode(rr->rdata + 3, tok);
			break;
		default:
			errx(1, "unsupported record type %s", type_to_string(type));
		}
		zone_add(z, rr);
	}
	free(buf);
	qsort(z->rr, z->rr_len, sizeof(z->rr[0]), rr_compare);

	return z;
}
