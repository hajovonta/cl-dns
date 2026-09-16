;;;; cl-sentinel configuration for cl-dns
;;;;
;;;; Only rules that are documented false positives for a DNS/DNSSEC protocol
;;;; library are disabled here. Every genuine finding (non-constant-time
;;;; comparison, unbounded loops over untrusted input, O(n^2) list building,
;;;; hardcoded key material) has been fixed in the source, not suppressed.

(:disable-rules
 ;; weak-cipher: DNSSEC (RFC 4034/8624) and TSIG (RFC 8945) are wire protocols
 ;; that mandate specific digest algorithms. verify-ds / verify-rrsig must
 ;; compute SHA-256/384/512 digests to validate signatures produced by
 ;; authoritative servers; TSIG uses HMAC-SHA256/512. These are required for
 ;; protocol conformance, not weaknesses. Deprecated SHA-1 (DS digest type 1,
 ;; RSA algorithms 5/7) has already been removed from verify-ds and
 ;; verify-rrsig, which now reject those algorithms. HMAC is delegated to the
 ;; vetted cl-crypto-util library, and all MAC/digest comparisons use
 ;; cl-crypto-util:ct-equal (constant time).
 weak-cipher

 ;; consing-in-loop: the DNS wire-format encoders and decoders write octets
 ;; incrementally into pre-allocated fixed-size buffers (make-array + setf aref)
 ;; and occasionally concatenate small fixed byte sequences. This is the correct,
 ;; idiomatic pattern for packet (de)serialization and does not produce the
 ;; O(n^2) allocation this rule targets.
 consing-in-loop)
