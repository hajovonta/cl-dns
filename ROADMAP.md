# cl-dns Roadmap

## v0.1 — Core (done)

- [x] DNS wire protocol encode/decode
- [x] Standard record types (A, AAAA, MX, SRV, CNAME, NS, PTR, TXT, SOA, NAPTR)
- [x] UDP/TCP resolver with retry and timeout
- [x] TTL-respecting cache
- [x] DNS-over-TLS (DoT)
- [x] DNS-over-HTTPS (DoH)
- [x] mDNS queries and DNS-SD service discovery

## v0.2 — Robustness (done)

- [x] Name compression in encoding (pointer-based dedup)
- [x] EDNS0 (OPT record) support for larger payloads
- [x] Negative caching (NXDOMAIN with SOA minimum TTL)
- [x] Parallel resolution via bordeaux-threads
- [x] Configurable max cache size with LRU eviction
- [x] Connection pooling for DoT/DoH

## v0.3 — DNSSEC (done)

- [x] RRSIG, DNSKEY, DS record parsing
- [x] Signature validation (RSA/SHA-1/256/512, ECDSA P-256/P-384)
- [x] Trust anchor store and management
- [x] Full chain validation (RRSIG → DNSKEY → DS → parent)
- [x] DS digest verification (SHA-1, SHA-256, SHA-384)
- [x] Key tag computation (RFC 4034)

## v0.4 — Advanced (done)

- [x] Recursive resolver mode (iterative from root)
- [x] Zone transfer (AXFR)
- [x] Dynamic DNS updates (RFC 2136)
- [x] Happy Eyeballs (RFC 8305) — parallel A+AAAA with IPv6 preference
- [x] DNS cookie support (RFC 7873)

## v0.5 — Integration

- [ ] cl-irc-server: async hostname resolution for connecting clients
- [ ] cl-dtn: node discovery via DNS-SD
- [ ] cl-mqtt: broker discovery via SRV/DNS-SD
- [ ] cl-orchestrator: use cl-dns for SRV lookups instead of shelling out

## v0.6 — Hardening (done)

- [x] NSEC/NSEC3 authenticated denial of existence
- [x] TSIG authentication (RFC 2845) for secure updates/transfers
- [x] Pluggable transport abstraction (udp-transport, tcp-transport, tls-transport)
- [x] Condition system (dns-error, dns-timeout, dns-servfail, dns-nxdomain)
- [x] Query deduplication (collapse identical in-flight queries)
- [x] Persistent cache (save/load to disk)
- [x] IXFR incremental zone transfers
