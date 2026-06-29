# Parallel Resolution & Happy Eyeballs

```lisp
;; Resolve multiple names concurrently
(let ((r (make-instance 'cl-dns:resolver)))
  (cl-dns:resolve-parallel r
    '(("google.com" :a)
      ("github.com" :a)
      ("cloudflare.com" :aaaa)
      ("amazon.com" :mx))
    :timeout 3))
;; Returns a list of dns-message responses (or NIL for failures)

;; Happy Eyeballs (RFC 8305)
;; Returns addresses sorted with IPv6 first, IPv4 second
(let ((r (make-instance 'cl-dns:resolver)))
  (cl-dns:happy-eyeballs r "google.com"))
;; => ("2a00:1450:400d:..." "142.251.x.x")

;; Custom delay before IPv4 fallback (default 250ms)
(cl-dns:happy-eyeballs r "example.com" :delay 0.5 :timeout 3)

;; Use for connection establishment:
(let ((addrs (cl-dns:happy-eyeballs r "my-service.com")))
  (loop for addr in addrs
        do (handler-case
               (return (connect-to addr 443))
             (error () nil))))
```
