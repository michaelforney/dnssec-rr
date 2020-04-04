This repository contains a few tools for working with DNSSEC. The
tools are implemented using [BearSSL].

## Generating keys

You can generate your ZSK (zone-signing key) and KSK (key-signing
key) using the `brssl` tool:

```
$ brssl skey -gen ec:secp256r1 -rawpem zsk.pem
$ brssl skey -gen ec:secp256r1 -rawpem ksk.pem
```

## `dsfromkey`

This tool generates a `DS` record for the parent zone (usually used
for registrar configuration).

```
$ dsfromkey example.com. ksk.pem
example.com.    86400   IN      DS      5207 13 2 10a30f9f11818844a7df830b85e125c9868bd2917fb21907f7f3569bdf8934d7
```

## `signzone`

This tool signs records read from standard input.

```
$ signzone zsk.pem ksk.pem < example.com.zone
```

Not yet implemented.

[BearSSL]: https://bearssl.org
