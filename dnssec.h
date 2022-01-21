#include <bearssl.h>

#define BE32(x) (unsigned char[]){x >> 24, x >> 16, x >> 8, x}
#define BE16(x) (unsigned char[]){x >> 8, x}

enum {
	TYPE_A      = 1,
	TYPE_NS     = 2,
	TYPE_CNAME  = 5,
	TYPE_SOA    = 6,
	TYPE_MX     = 15,
	TYPE_TXT    = 16,
	TYPE_AAAA   = 28,
	TYPE_SRV    = 33,
	TYPE_DS     = 43,
	TYPE_SSHFP  = 44,
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

struct key *key_new_from_file(const char *, int);

/* domain names */
enum {
	LABEL_MAX = 63,
	DNAME_MAX = 255,
};

size_t dname_parse(const char *, char **, unsigned char[static DNAME_MAX], const unsigned char *, size_t);
int dname_compare(const unsigned char *, const unsigned char *);
int dname_print(const unsigned char *);
int dname_labels(const unsigned char *);

/* DNSSEC record types */
enum {
	DNSKEY_SEP  = 1 << 0,
	DNSKEY_ZONE = 1 << 8,
};

struct dnskey {
	unsigned flags;
	int protocol;
	int algorithm;
	size_t data_len;
	unsigned char data[];
};

struct dnskey *dnskey_new(unsigned, const struct key *);
unsigned dnskey_tag(const struct dnskey *);

/* base16 (hexadecimal) */
size_t base16_decode(unsigned char *, const char *);

/* base64 */
#define base64_length(n) (((n) + 2) / 3 * 4)
void base64_encode(char *, const unsigned char *, size_t);
size_t base64_decode(unsigned char *, const char *);

/* zone */
struct rr {
	unsigned char name[DNAME_MAX];
	size_t name_len;
	int type;
	int class;
	unsigned long ttl;
	size_t rdata_len;
	unsigned char rdata[];
};

struct zone {
	unsigned long minimum_ttl;
	struct rr **rr;
	size_t rr_len;
};

int zone_parse(struct zone *, const char *, char *, size_t);
