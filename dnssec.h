#include <bearssl.h>

enum {
	CLASS_IN = 1,
};

int class_from_string(const char *);
const char *class_to_string(int);

enum {
	ALGORITHM_ECDSAP256SHA256 = 13,
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
	unsigned char data[];
};

struct dnskey *dnskey_new(unsigned, const struct key *);
void dnskey_hash(const struct dnskey *, const br_hash_class **);
unsigned dnskey_tag(const struct dnskey *);
