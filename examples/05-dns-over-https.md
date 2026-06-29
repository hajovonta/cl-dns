# DNS-over-HTTPS (DoH)

```lisp
;; Requires dexador: (ql:quickload :dexador)

;; Query Cloudflare's DoH endpoint
(let* ((query (cl-dns:make-query "example.com" :a))
       (bytes (cl-dns:encode-message query))
       (resp (cl-dns:doh-query "https://cloudflare-dns.com/dns-query" bytes)))
  ;; resp is already a decoded dns-message
  (cl-dns::message-answers resp))

;; Google's DoH
(cl-dns:doh-query "https://dns.google/dns-query" bytes :timeout 10)

;; Custom timeout
(cl-dns:doh-query "https://doh.opendns.com/dns-query" bytes :timeout 3)
```
