# Basic Resolution

```lisp
(ql:quickload :cl-dns)

;; Create a resolver with default nameservers (8.8.8.8, 8.8.4.4)
(defvar *resolver* (make-instance 'cl-dns:resolver))

;; A record lookup
(let ((resp (cl-dns:resolve *resolver* "example.com" :a)))
  (dolist (rr (cl-dns::message-answers resp))
    (format t "~A -> ~A (TTL ~D)~%"
            (cl-dns::rr-name rr) (cl-dns::rr-rdata rr) (cl-dns::rr-ttl rr))))

;; AAAA record
(cl-dns:resolve *resolver* "google.com" :aaaa)

;; MX record
(cl-dns:resolve *resolver* "gmail.com" :mx)

;; SRV record (service discovery)
(cl-dns:resolve *resolver* "_http._tcp.example.com" :srv)

;; TXT record (SPF, DKIM, etc.)
(cl-dns:resolve *resolver* "example.com" :txt)

;; Custom nameservers
(defvar *cf-resolver*
  (make-instance 'cl-dns:resolver
    :nameservers '("1.1.1.1" "1.0.0.1")))

;; Timeout and retries
(cl-dns:resolve *resolver* "slow.example.com" :a
  :timeout 10 :retries 5)
```
