# cl-dns

Async DNS resolver for Common Lisp with DNS-over-HTTPS, DNS-over-TLS, DNSSEC validation, and mDNS/DNS-SD support.

## Features

- [Full DNS wire protocol](examples/16-wire-protocol.md) with name compression (all standard record types)
- [Recursive resolver](examples/01-basic-resolution.md) with configurable timeout, retry, and nameserver rotation
- [Iterative resolver](examples/07-iterative-resolution.md) (from root servers, following delegations)
- [Parallel resolution & Happy Eyeballs](examples/02-parallel-and-happy-eyeballs.md) (RFC 8305, IPv6-preferred)
- [Caching](examples/03-caching.md) with TTL respect, LRU eviction, negative caching, and persistence
- [DNS-over-TLS](examples/04-dns-over-tls.md) (DoT, RFC 7858) with connection pooling
- [DNS-over-HTTPS](examples/05-dns-over-https.md) (DoH, RFC 8484)
- [mDNS/DNS-SD](examples/06-mdns-service-discovery.md) for local service discovery
- [DNSSEC validation](examples/08-dnssec.md) (RRSIG, DNSKEY, DS, NSEC/NSEC3 chain verification)
- [Dynamic DNS updates](examples/09-dynamic-updates.md) (RFC 2136)
- [Zone transfers](examples/10-zone-transfers.md) (AXFR and IXFR)
- [TSIG authentication](examples/11-tsig.md) (RFC 2845, HMAC-SHA256/512/1)
- [DNS cookies](examples/12-dns-cookies.md) (RFC 7873, anti-spoofing)
- [Pluggable transports](examples/13-transports.md) (UDP, TCP, TLS — mockable for testing)
- [Query deduplication](examples/14-query-dedup.md) (collapse identical in-flight queries)
- [Condition system](examples/15-error-handling.md) (dns-error, dns-timeout, dns-servfail, dns-nxdomain)
- EDNS0 support (OPT record, >512 byte UDP payloads, DNSSEC OK bit)

Supported record types: A, AAAA, MX, SRV, CNAME, NS, PTR, TXT, SOA, NAPTR, RRSIG, DNSKEY, DS, NSEC, NSEC3

## Quick Start

```lisp
(ql:quickload :cl-dns)

(let ((r (make-instance 'cl-dns:resolver)))
  ;; Simple lookup
  (cl-dns:resolve r "example.com" :a)

  ;; Parallel A+AAAA with IPv6 preference
  (cl-dns:happy-eyeballs r "google.com")

  ;; Iterative from root (authoritative)
  (cl-dns:resolve-iterative "example.com" :a))
```

## Dependencies

- usocket
- bordeaux-threads
- cl+ssl
- split-sequence
- ironclad
- dexador (optional, for DoH)

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                            cl-dns                                 │
├────────────┬───────────┬─────────┬──────┬──────┬─────┬──────────┤
│  resolver  │ iterative │ dynamic │ doh  │ dot  │mdns │   dedup  │
├────────────┴───────────┴─────────┼──────┴──────┴─────┴──────────┤
│   cache    │  dnssec   │  nsec   │  tsig  │ conditions │  pool  │
├────────────┴───────────┴─────────┴────────┴────────────┴────────┤
│                      transport / protocol                        │
└──────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| protocol | Wire format encode/decode, record types, EDNS0, cookies |
| cache | TTL cache, LRU eviction, negative caching, persistence |
| resolver | Recursive resolver, parallel queries, Happy Eyeballs |
| iterative | Iterative resolution from root servers |
| dnssec | RRSIG/DNSKEY/DS validation, trust anchors |
| nsec | NSEC/NSEC3 authenticated denial of existence |
| tsig | HMAC-based transaction signatures |
| dynamic | DNS UPDATE (RFC 2136), AXFR/IXFR zone transfers |
| transport | Pluggable UDP/TCP/TLS transport abstraction |
| pool | Connection pooling for DoT/DoH |
| dedup | In-flight query deduplication |
| conditions | DNS error condition hierarchy |
| doh | DNS-over-HTTPS |
| dot | DNS-over-TLS |
| mdns | Multicast DNS and DNS-SD service discovery |

## Examples

See the [examples/](examples/) directory for detailed usage of every feature.

## License

MIT — see [LICENSE](LICENSE)
