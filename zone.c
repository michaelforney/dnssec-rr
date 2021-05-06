#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "dnssec.h"

struct input {
	char *name;
	FILE *file;
	unsigned line;
	unsigned char origin[DNAME_MAX], domain[DNAME_MAX];
	size_t origin_len, domain_len;
	struct input *next;
};

struct parser {
	struct input *input;
	/* current line */
	char *buf, *pos, *end;
	size_t buf_len;
	/* temporary buffer for record data */
	char *tmp;
	size_t tmp_len;
	/* $TTL value */
	unsigned long ttl;
	/* parentheses nesting level */
	unsigned paren;
	int class, err;
	char *errbuf;
	size_t errlen;
};

static struct rr *
rr_new(size_t rdata_len)
{
	struct rr *rr;

	if (!(rr = malloc(sizeof(*rr) + rdata_len)))
		return NULL;
	rr->rdata_len = rdata_len;
	return rr;
}

static void
parse_error(struct parser *p, const char *pos, const char *fmt, ...)
{
	if (!p->err && p->errbuf) {
		size_t off = 0;
		if (pos) {
			int ret = snprintf(p->errbuf, p->errlen, "%s:%u:%td: ", p->input->name, p->input->line, pos - p->buf + 1);
			if (ret >= 0)
				off += ret;
		}
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(p->errbuf + off, p->errlen - off, fmt, ap);
		va_end(ap);
	}
	p->err = 1;
}

static struct input *
parse_open(struct parser *p, const char *name)
{
	struct input *input = calloc(1, sizeof(*input));
	if (!input || !(input->name = strdup(name ? name : "<stdin>"))) {
		parse_error(p, NULL, "%s", strerror(errno));
		goto err;
	}
	if (!name) {
		input->file = stdin;
	} else if (!(input->file = fopen(name, "r"))) {
		parse_error(p, NULL, "open %s: %s", name, strerror(errno));
		goto err;
	}
	return input;

err:
	if (input) {
		free(input->name);
		free(input);
	}
	return NULL;
}

static int
parse_init(struct parser *p, const char *name, char *errbuf, size_t errlen)
{
	memset(p, 0, sizeof(*p));
	p->errbuf = errbuf;
	p->errlen = errlen;
	p->class = CLASS_IN;
	if (!(p->input = parse_open(p, name)))
		return -1;
	return 0;
}

static int
next_line(struct parser *p)
{
	ssize_t ret;

	while (p->input && (ret = getline(&p->buf, &p->buf_len, p->input->file)) < 0) {
		if (ferror(p->input->file)) {
			parse_error(p, NULL, "read %s: %s", p->input->name, strerror(errno));
			return -1;
		}
		struct input *next = p->input->next;
		if (p->input->file != stdin)
			fclose(p->input->file);
		free(p->input->name);
		free(p->input);
		p->input = next;
	}
	if (!p->input)
		return -1;
	if (ret && p->buf[ret - 1] == '\n')
		p->buf[--ret] = '\0';
	p->pos = p->buf;
	p->end = p->buf + ret;
	++p->input->line;
	return 0;
}

/* skip forward to the next non-whitespace character, crossing line
 * boundaries only if inside parentheses */
static int
next_item(struct parser *p)
{
	for (;;) {
		while (p->pos < p->end && (*p->pos == ' ' || *p->pos == '\t'))
			++p->pos;
		if (p->pos == p->end) {
			if (p->paren == 0)
				return 0;
			if (next_line(p) != 0)
				return -1;
			continue;
		}
		switch (*p->pos) {
		case '(':
			++p->pos;
			++p->paren;
			break;
		case ')':
			++p->pos;
			--p->paren;
			break;
		case ';':
			p->pos = p->end;
			break;
		default:
			return 1;
		}
	}
}

static char *
parse_item(struct parser *p, size_t *len)
{
	char *pos, *item;

	if (next_item(p) != 1)
		return NULL;
	pos = p->pos;
	while (pos < p->end && *pos != '\t' && *pos != ' ')
		++pos;
	if (pos == p->pos)
		return NULL;
	if (len)
		*len = pos - p->pos;
	if (pos < p->end)
		*pos++ = '\0';
	item = p->pos;
	p->pos = pos;
	return item;
}

static size_t
parse_data(struct parser *p)
{
	char *item, *new_tmp;
	size_t len = 0, new_len, item_len;

	while ((item = parse_item(p, &item_len))) {
		new_len = len + item_len;
		if (new_len + 1 > p->tmp_len) {
			if (!(new_tmp = realloc(p->tmp, new_len + 1))) {
				parse_error(p, NULL, "%s", strerror(errno));
				return 0;
			}
			p->tmp = new_tmp;
			p->tmp_len = new_len + 1;
		}
		memcpy(p->tmp + len, item, item_len);
		len = new_len;
	}
	if (p->err || !len)
		return 0;
	p->tmp[len] = '\0';
	return len;
}

static size_t
parse_dname(struct parser *p, unsigned char buf[static DNAME_MAX], const char **err)
{
	if (next_item(p) != 1) {
		if (err)
			*err = "expected domain name";
		return 0;
	}
	size_t len = dname_parse(p->pos, &p->pos, buf, p->input->origin, p->input->origin_len);
	if (!len) {
		if (err)
			*err = "invalid domain name";
		return 0;
	}
	*err = NULL;
	return len;
}

static unsigned long
parse_int(struct parser *p, const char **err)
{
	char *end;
	unsigned long val;

	if (next_item(p) != 1) {
		if (err)
			*err = "expected integer";
		return 0;
	}
	val = strtoul(p->pos, &end, 10);
	if (*end && *end != ' ' && *end != '\t' && *end != ';') {
		if (err)
			*err = "invalid integer";
		return 0;
	}
	*err = NULL;
	p->pos = end;
	return val;
}

static struct rr *
parse_rr(struct parser *p)
{
	struct rr *rr = NULL;
	const char *err;
	char *item;
	unsigned char dname[DNAME_MAX], *rdata;
	size_t dname_len;
	int type, class;
	unsigned long ttl;

again:
	for (;;) {
		if (next_line(p) != 0)
			goto err;
		if (next_item(p) == 0)
			continue;
		if (p->err)
			return NULL;
		if (p->pos != p->buf)
			break;
		if (*p->pos != '$') {
			p->input->domain_len = parse_dname(p, p->input->domain, &err);
			if (p->input->domain_len == 0) {
				parse_error(p, p->pos, "invalid RR: %s", err);
				goto err;
			}
			break;
		}
		/* directive */
		item = parse_item(p, NULL);
		if (!item) {
			parse_error(p, p->pos, "expected directive");
			goto err;
		}
		if (strcmp(item, "$ORIGIN") == 0) {
			p->input->origin_len = parse_dname(p, p->input->origin, &err);
			if (p->input->origin_len == 0) {
				parse_error(p, p->pos, "%s", err);
				goto err;
			}
		} else if (strcmp(item, "$INCLUDE") == 0) {
			if (!(item = parse_item(p, NULL))) {
				parse_error(p, p->pos, "expected filename");
				goto err;
			}
			struct input *input = parse_open(p, item);
			if (!input)
				goto err;
			input->next = p->input;
			p->input = input;
			if (next_item(p) == 1) {
				p->input->origin_len = parse_dname(p, p->input->origin, &err);
				if (p->input->origin_len == 0) {
					parse_error(p, p->pos, "%s", err);
					goto err;
				}
			}
			if (p->err)
				goto err;
		} else if (strcmp(item, "$TTL") == 0) {  /* RFC 2308 */
			p->ttl = parse_int(p, &err);
			if (err) {
				parse_error(p, p->pos, "%s", err);
				goto err;
			}
		} else {
			parse_error(p, item, "unknown directive '%s'", item);
			goto err;
		}
		if (next_item(p) != 0) {
			parse_error(p, p->pos, "unexpected item after directive");
			goto err;
		}
	}
	if (p->input->domain_len == 0) {
		parse_error(p, p->buf, "missing domain name");
		goto err;
	}
	class = 0;
	ttl = 0;
	item = parse_item(p, NULL);
	for (int i = 0; i < 2; ++i) {
		if (!class && (class = class_from_string(item))) {
			/* nothing */
		} else if (!ttl && isdigit(item[0])) {
			char *end;
			ttl = strtoul(item, &end, 10);
			if (*end) {
				parse_error(p, item, "invalid TTL");
				goto err;
			}
		} else {
			break;
		}
		item = parse_item(p, NULL);
		if (!item) {
			parse_error(p, p->pos, "expected record type, class, or TTL");
			goto err;
		}
	}
	if (!ttl && !p->ttl) {
		parse_error(p, item, "expected TTL");
		goto err;
	}
	if (!(type = type_from_string(item))) {
		parse_error(p, item, "unsupported record type '%s'", item);
		goto err;
	}
	if (next_item(p) != 1) {
		parse_error(p, p->pos, "invalid %s: expected RDATA", type_to_string(type));
		goto err;
	}
	if (p->pos[0] == '\\' && p->pos[1] == '#' && (!p->pos[2] || p->pos[2] == ' ' || p->pos[2] == '\t' || p->pos[2] == ';')) {
		/* RFC 3597 generic record format */
		p->pos += 2;
		size_t len = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid generic RDATA: %s", err);
			goto err;
		}
		if (!(rr = rr_new(len * 2))) {
			parse_error(p, NULL, "%s", strerror(errno));
			goto err;
		}
		size_t data_len = parse_data(p);
		if (data_len != len * 2)
			parse_error(p, p->pos, "invalid generic RDATA: data length differs from specified length");
		if (p->err)
			goto err;
		if (base16_decode(rr->rdata, p->tmp) == 0)
			parse_error(p, p->pos, "invalid generic RDATA: invalid hex string");
	} else switch (type) {
	case TYPE_A:
		if (!(rr = rr_new(4))) {
			parse_error(p, NULL, "%s", strerror(errno));
			goto err;
		}
		if (!(item = parse_item(p, NULL))) {
			parse_error(p, p->pos, "invalid A: expected IPv4 address");
			goto err;
		}
		if (inet_pton(AF_INET, item, rr->rdata) != 1) {
			parse_error(p, item, "invalid A: invalid IPv4 address");
			goto err;
		}
		break;
	case TYPE_NS:
	case TYPE_CNAME:
		if ((dname_len = parse_dname(p, dname, &err)) == 0) {
			parse_error(p, p->pos, "invalid %s: %s", type_to_string(type), err);
			return NULL;
		}
		if (!(rr = rr_new(dname_len))) {
			parse_error(p, NULL, "%s", strerror(errno));
			return NULL;
		}
		memcpy(rr->rdata, dname, dname_len);
		break;
	case TYPE_SOA: {
		unsigned char mname[DNAME_MAX], rname[DNAME_MAX];
		size_t mname_len, rname_len;

		if ((mname_len = parse_dname(p, mname, &err)) == 0) {
			parse_error(p, p->pos, "invalid SOA: name server: %s");
			goto err;
		}
		if ((rname_len = parse_dname(p, rname, &err)) == 0) {
			parse_error(p, p->pos, "invalid SOA: owner mailbox: %s");
			goto err;
		}
		if (!(rr = rr_new(mname_len + rname_len + 20))) {
			parse_error(p, NULL, "%s", strerror(errno));
			goto err;
		}
		rdata = rr->rdata;
		memcpy(rdata, mname, mname_len);
		rdata += mname_len;
		memcpy(rdata, rname, rname_len);
		rdata += rname_len;

		unsigned long val;

		/* serial */
		val = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid SOA: serial: %s", err);
			goto err;
		}
		memcpy(rdata, &(uint32_t){htonl(val)}, 4);
		rdata += 4;

		/* refresh */
		val = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid SOA: refresh interval: %s", err);
			goto err;
		}
		memcpy(rdata, &(uint32_t){htonl(val)}, 4);
		rdata += 4;

		/* retry */
		val = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid SOA: retry interval: %s", err);
			goto err;
		}
		memcpy(rdata, &(uint32_t){htonl(val)}, 4);
		rdata += 4;

		/* expire */
		val = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid SOA: expire interval: %s", err);
			goto err;
		}
		memcpy(rdata, &(uint32_t){htonl(val)}, 4);
		rdata += 4;

		/* minimum TTL */
		val = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid SOA: minimum TTL: %s", err);
			goto err;
		}
		memcpy(rdata, &(uint32_t){htonl(val)}, 4);
		rdata += 4;
		break;
	}
	case TYPE_MX: {
		unsigned preference = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid MX: preference: %s", err);
			goto err;
		}
		if ((dname_len = parse_dname(p, dname, &err)) == 0) {
			parse_error(p, p->pos, "invalid MX: %s");
			goto err;
		}
		if (!(rr = rr_new(2 + dname_len))) {
			parse_error(p, NULL, "%s", strerror(errno));
			goto err;
		}
		memcpy(rr->rdata, &(uint16_t){htons(preference)}, 2);
		memcpy(rr->rdata + 2, dname, dname_len);
		break;
	}
	case TYPE_AAAA:
		if (!(rr = rr_new(16))) {
			parse_error(p, NULL, "%s", strerror(errno));
			goto err;
		}
		if (!(item = parse_item(p, NULL))) {
			parse_error(p, p->pos, "invalid AAAA: expected IPv6 address");
			goto err;
		}
		if (inet_pton(AF_INET6, item, rr->rdata) != 1) {
			parse_error(p, p->pos, "invalid AAAA: invalid IPv6 address");
			goto err;
		}
		break;
	/* RFC 2782 */
	case TYPE_SRV: {
		unsigned priority = parse_int(p, &err);
		if (p->err) {
			parse_error(p, p->pos, "invalid SRV: priority: %s", err);
			return NULL;
		}
		unsigned weight = parse_int(p, &err);
		if (p->err) {
			parse_error(p, p->pos, "invalid SRV: weight: %s", err);
			return NULL;
		}
		unsigned port = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid SRV: port: %s", err);
			return NULL;
		}
		if (!(dname_len = parse_dname(p, dname, &err))) {
			parse_error(p, p->pos, "invalid SRV: %s", err);
			return NULL;
		}
		if (!(rr = rr_new(6 + dname_len))) {
			parse_error(p, NULL, "%s", strerror(errno));
			return NULL;
		}
		memcpy(rr->rdata, &(uint16_t){htons(priority)}, 2);
		memcpy(rr->rdata + 2, &(uint16_t){htons(weight)}, 2);
		memcpy(rr->rdata + 4, &(uint16_t){htons(port)}, 2);
		memcpy(rr->rdata + 6, dname, dname_len);
		break;
	}
	/* RFC 4255 */
	case TYPE_SSHFP: {
		int algorithm = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid SSHFP: algorithm: %s", err);
			goto err;
		}
		int fptype = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid SSHFP: fingerprint type: %s", err);
			goto err;
		}
		size_t len = parse_data(p);
		if (len == 0) {
			parse_error(p, p->pos, "invalid SSHFP: expected fingerprint data");
			goto err;
		}
		if (len % 2) {
			parse_error(p, p->pos, "invalid SSHFP: fingerprint data must have even length");
			goto err;
		}
		if (!(rr = rr_new(2 + len / 2))) {
			parse_error(p, NULL, "%s", strerror(errno));
			goto err;
		}
		rr->rdata[0] = algorithm;
		rr->rdata[1] = fptype;
		len = base16_decode(rr->rdata + 2, p->tmp);
		if (len == 0) {
			parse_error(p, p->pos, "invalid SSHFP: invalid fingerprint hex string");
			goto err;
		}
		rr->rdata_len = 2 + len;
		break;
	}
	/* RFC 4034 */
	case TYPE_RRSIG:
		/* skip */
		while (next_item(p) == 1)
			++p->pos;
		if (p->err)
			goto err;
		goto again;
	case TYPE_DNSKEY: {
		unsigned flags = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid DNSKEY: flags: %s", err);
			goto err;
		}
		int protocol = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid DNSKEY: protocol: %s", err);
			goto err;
		}
		int algorithm = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid DNSKEY: algorithm: %s", err);
			goto err;
		}
		size_t len = parse_data(p);
		if (len == 0)
			parse_error(p, p->pos, "invalid DNSKEY: expected public key");
		if (len % 4)
			parse_error(p, p->pos, "invalid DNSKEY: public key base64 has invalid length");
		if (p->err)
			goto err;
		rr = rr_new(4 + len * 3 / 4);
		memcpy(rr->rdata, &(uint16_t){htons(flags)}, 2);
		rr->rdata[2] = protocol;
		rr->rdata[3] = algorithm;
		len = base64_decode(rr->rdata + 4, p->tmp);
		if (len == 0) {
			parse_error(p, p->pos, "invalid DNSKEY: invalid public key base64");
			goto err;
		}
		rr->rdata_len = 4 + len;
		break;
	}
	case TYPE_NSEC:
		/* XXX: only types up to 255 are supported for now */
		if ((dname_len = parse_dname(p, dname, &err)) == 0) {
			parse_error(p, p->pos, "invalid NSEC: %s", err);
			goto err;
		}
		if (!(rr = rr_new(dname_len + 34))) {
			parse_error(p, NULL, "%s", strerror(errno));
			goto err;
		}
		rdata = rr->rdata;
		memcpy(rdata, dname, dname_len);
		rdata += dname_len;
		memset(rdata, 0, 34);
		while ((item = parse_item(p, NULL))) {
			int type = type_from_string(item);
			if (type > 255) {
				parse_error(p, item, "invalid NSEC: unsupported record type %d", type);
				goto err;
			}
			rdata[2 + type / 8] |= 0x80 >> type % 8;
			if (type / 8 + 1 > rdata[1])
				rdata[1] = type / 8 + 1;
		}
		if (p->err)
			goto err;
		rr->rdata_len -= 32 - rdata[1];
		break;
	case TYPE_TLSA: {
		int usage = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid TLSA: usage: %s", err);
			goto err;
		}
		int selector = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid TLSA: selector: %s", err);
			goto err;
		}
		int match = parse_int(p, &err);
		if (err) {
			parse_error(p, p->pos, "invalid TLSA: match: %s", err);
			goto err;
		}
		size_t len = parse_data(p);
		if (len == 0) {
			parse_error(p, p->pos, "invalid TLSA: expected certificate association data");
			goto err;
		}
		if (len % 2) {
			parse_error(p, p->pos, "invalid TLSA: certificate association data must have even length");
			goto err;
		}
		if (!(rr = rr_new(3 + len / 2))) {
			parse_error(p, NULL, "%s", strerror(errno));
			goto err;
		}
		rr->rdata[0] = usage;
		rr->rdata[1] = selector;
		rr->rdata[2] = match;
		len = base16_decode(rr->rdata + 3, p->tmp);
		if (len == 0) {
			parse_error(p, p->pos, "invalid TLS: invalid certificate association data hex string");
			goto err;
		}
		rr->rdata_len = 3 + len;
		break;
	}
	default:
		parse_error(p, p->pos, "unsupported record type '%s'", type_to_string(type));
		goto err;
	}
	memcpy(rr->name, p->input->domain, p->input->domain_len);
	rr->name_len = p->input->domain_len;
	rr->type = type;
	rr->class = p->class = class ? class : p->class;
	rr->ttl = ttl ? ttl : p->ttl;
	if (next_item(p) != 0) {
		parse_error(p, p->pos, "unexpected item after record");
		goto err;
	}
	return rr;

err:
	free(rr);
	return NULL;
}

/* canonical ordering of domain names */
static int
rr_compare(const void *p1, const void *p2)
{
	const struct rr *rr1 = *(const struct rr **)p1, *rr2 = *(const struct rr **)p2;

	int ret = dname_compare(rr1->name, rr2->name);
	if ((ret = dname_compare(rr1->name, rr2->name)))
		return ret;
	/* sort SOA before other record types so that it is always first in the zone */
	if (rr1->type != rr2->type)
		return rr1->type == TYPE_SOA ? -1 : rr2->type == TYPE_SOA ? 1 : rr1->type - rr2->type;
	if (rr1->class != rr2->class)
		return rr1->class - rr2->class;
	size_t len = rr1->rdata_len < rr2->rdata_len ? rr1->rdata_len : rr2->rdata_len;
	if ((ret = memcmp(rr1->rdata, rr2->rdata, len)) != 0 || rr1->rdata_len == rr2->rdata_len)
		return ret;
	return len == rr1->rdata_len ? -1 : 1;
}

static int
zone_add(struct zone *z, struct rr *rr)
{
	struct rr **rrs;

	if (!(z->rr_len & (z->rr_len - 1))) {
		if (!(rrs = realloc(z->rr, (z->rr_len ? z->rr_len * 2 : 1) * sizeof(rr))))
			return -1;
		z->rr = rrs;
	}
	z->rr[z->rr_len++] = rr;
	return 0;
}

int
zone_parse(struct zone *z, const char *name, char *errbuf, size_t errlen)
{
	struct parser p;
	struct rr *rr;

	z->rr = NULL;
	z->rr_len = 0;
	if (parse_init(&p, name, errbuf, errlen) != 0)
		goto err;
	while ((rr = parse_rr(&p))) {
		if ((rr->type == TYPE_SOA) != (z->rr_len == 0)) {
			snprintf(errbuf, errlen, "exactly one SOA record required at start of zone");
			goto err;
		}
		if (rr->type == TYPE_SOA) {
			uint32_t minimum_ttl;
			memcpy(&minimum_ttl, rr->rdata + (rr->rdata_len - 4), 4);
			z->minimum_ttl = ntohl(minimum_ttl);
		}
		if (zone_add(z, rr) != 0) {
			snprintf(errbuf, errlen, "%s", strerror(errno));
			goto err;
		}
	}
	if (p.err)
		goto err;
	qsort(z->rr, z->rr_len, sizeof(z->rr[0]), rr_compare);
	free(p.buf);
	free(p.tmp);
	return 0;
err:
	while (p.input) {
		struct input *next = p.input->next;
		fclose(p.input->file);
		free(p.input->name);
		free(p.input);
		p.input = next;
	}
	free(p.buf);
	free(p.tmp);
	return -1;
}
