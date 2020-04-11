#include <stdio.h>
#include <bearssl.h>

enum {
	TYPE_A      = 1,
	TYPE_NS     = 2,
	TYPE_CNAME  = 5,
	TYPE_SOA    = 6,
	TYPE_MX     = 15,
	TYPE_AAAA   = 28,
	TYPE_SRV    = 33,
	TYPE_DS     = 43,
	TYPE_RRSIG  = 46,
	TYPE_NSEC   = 47,
	TYPE_DNSKEY = 48,
	TYPE_TLSA   = 52,
};

int type_from_string(const char *);
const char *type_to_string(int);

enum {
	CLASS_IN = 1,
};

int class_from_string(const char *);
const char *class_to_string(int);

enum {
	ALGORITHM_DSA             = 3,
	ALGORITHM_RSASHA1         = 5,
	ALGORITHM_RSASHA256       = 8,
	ALGORITHM_RSASHA512       = 10,
	ALGORITHM_ECDSAP256SHA256 = 13,
	ALGORITHM_ECDSAP384SHA384 = 14,
	ALGORITHM_ED25519         = 15,
};

int algorithm_from_string(const char *);
const char *algorithm_to_string(int);

enum {
	DIGEST_SHA1   = 1,
	DIGEST_SHA256 = 2,
	DIGEST_SHA384 = 4,
};

int digest_from_string(const char *);

/* secret key */
struct key {
	int algorithm;
	union {
		br_ec_private_key ec;
		br_rsa_private_key rsa;
	};
	unsigned char data[];
};

struct key *key_new_from_file(const char *);

/* domain names */
void dname_hash(const char *, const br_hash_class **);
unsigned char *dname_encode(unsigned char *, const char *);
int dname_labels(const char *);

/* DNSSEC record types */
enum {
	DNSKEY_SEP  = 1 << 0,
	DNSKEY_ZONE = 1 << 8,
};

struct dnskey {
	unsigned flags;
	int protocol;
	int algorithm;
	size_t data_length;
	unsigned char data[];
};

struct dnskey *dnskey_new(unsigned, const struct key *);
unsigned dnskey_tag(const struct dnskey *);

/* base16 (hexadecimal) */
size_t base16_decode(unsigned char *, const char *);

/* base64 */
void base64_encode(char *, const unsigned char *, size_t);
size_t base64_decode(unsigned char *, const char *);

/* zone */
struct rr {
	char *name;
	int type;
	int class;
	unsigned long ttl;
	size_t rdata_length;
	unsigned char rdata[];
};

struct zone {
	struct {
		unsigned long minimum_ttl;
	} soa;
	struct rr **rr;
	size_t rr_length;
};

struct zone *zone_new_from_file(const char *, FILE *);
