This repository contains a few tools for working with DNSSEC. The
tools are implemented using [BearSSL].

## Generating keys

You can generate your ZSK (zone-signing key) and KSK (key-signing
key) using the `brssl` tool:

```
$ brssl skey -gen ec:secp256r1 -rawpem zsk.pem
$ brssl skey -gen ec:secp256r1 -rawpem ksk.pem
```

## ds

This tool generates a `DS` record for the parent zone (usually used
for registrar configuration).

```
$ ds example.com. ksk.pem
example.com.    86400   IN      DS      5207 13 2 10a30f9f11818844a7df830b85e125c9868bd2917fb21907f7f3569bdf8934d7
```

## dnskey

This tool generates a `DNSKEY` record from a private key.

```
$ dnskey -k example.com. ksk.pem
example.com.    86400   IN      DNSKEY  257 3 13 0KcqMTP78j9XbR4FoglT9t03IIMtsRO321K01QlNAXuYmI/YlLU9elwEwYfAtPJ1GMCpXiJWrCd2Di1nATypCA==
$ dnskey example.com. zsk.pem
example.com.    86400   IN      DNSKEY  256 3 13 FH+S2VOGBc7NAZU/1yL271VjUDzYEh3Ehv4Ii2GoFVTFwcHA/o3kdZS5N+l2CVK4N+6bqsiHwcqtmydSMVcziQ==
```

[BearSSL]: https://bearssl.org
