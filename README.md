This repository contains a few tools for working with DNSSEC. The
tools are implemented using [BearSSL].

## Generating keys

You can generate your ZSK (zone-signing key) and KSK (key-signing
key) using the `brssl` tool:

```
$ brssl skey -gen ec:secp256r1 -rawpem zsk.pem
$ brssl skey -gen ec:secp256r1 -rawpem ksk.pem
```

You can also use `-gen rsa[:size]` to generate RSA keys.

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

## nsec

This tool generates `NSEC` records for a zone, linking the domain names together.

```
$ { cat <<EOF; dnskey -k example.com. ksk.pem; dnskey example.com. zsk.pem; } | nsec
example.com.		86400	IN	SOA	ns1.example.com. root.example.com. 2020040900 7200 900 1209600 1200
abc.example.com.	86400	IN	A	1.2.3.4
def.example.com.	86400	IN	A	5.6.7.8
EOF
example.com.    1200    IN      NSEC    abc.example.com. SOA RRSIG NSEC DNSKEY
abc.example.com.        1200    IN      NSEC    def.example.com. A RRSIG NSEC
def.example.com.        1200    IN      NSEC    example.com. A RRSIG NSEC
```

## rrsig

This tool signs the records in a zone, generating `RRSIG` records.

```
$ { cat <<EOF; dnskey -k example.com. ksk.pem; dnskey example.com. zsk.pem; } > example.com.zone
example.com.		86400	IN	SOA	ns1.example.com. root.example.com. 2020040900 7200 900 1209600 1200
abc.example.com.	86400	IN	A	1.2.3.4
def.example.com.	86400	IN	A	5.6.7.8
EOF
$ rrsig -k ksk.pem < example.com.zone
example.com.    86400   IN      RRSIG   DNSKEY 13 2 86400 20200510061125 20200410061125 5207 example.com. aM2PVY7JIgyVZIzE8J2c427ju3VRCPjdIeDwkCqa9ITI4n9WrCL50dLL5NC7E1vSERA6FUNybV0skjXoX6mLbA==
$ rrsig -z zsk.pem < example.com.zone
example.com.    86400   IN      RRSIG   SOA 13 2 86400 20200510061143 20200410061143 28335 example.com. QR8IwdtcyApF13FP7dOpoQDOpcXasa2zBdlvLWl8X6j5d3COv13B/mV2/T5uPMIEFJEBvapIHsk0XUuHPzbe3g==
abc.example.com.        86400   IN      RRSIG   A 13 3 86400 20200510061143 20200410061143 28335 example.com. MaSqG7b1NBDDfNWWXHQ6mVdamT50jzIF8YZpbWZ38w4PfIvSBLrx1zW7NgxiUcTv/2DhGrhFfuZENF8Y07eNPw==
def.example.com.        86400   IN      RRSIG   A 13 3 86400 20200510061143 20200410061143 28335 example.com. Izl/hwxnmwtmYTDVXMJIhsCLQGM2Icdz54Ap5akxHrhooAsxG8rHz4HikAureBSTVm+gO3hZ2+Cx2w7sIBr4Og==
```

## Current limitations

- Only a few common record types are supported.
- The zone parser is very limited; it only accepts one record per line, with no parentheses and no comments.

[BearSSL]: https://bearssl.org
