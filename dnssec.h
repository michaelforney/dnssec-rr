#include <bearssl.h>

enum {
	TYPE_A      = 1,
	TYPE_NS     = 2,
	TYPE_CNAME  = 5,
	TYPE_SOA    = 6,
	TYPE_MX     = 15,
	TYPE_AAAA   = 28,
	TYPE_DS     = 43,
	TYPE_RRSIG  = 46,
	TYPE_NSEC   = 47,
	TYPE_DNSKEY = 48,
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

/* DNSSEC record types */
void dname_hash(const char *, const br_hash_class **);

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
void dnskey_hash(const struct dnskey *, const br_hash_class **);
unsigned dnskey_tag(const struct dnskey *);
