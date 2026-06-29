# Iterative Resolution

```lisp
;; Resolve from root servers, following delegations
;; (does not use a recursive resolver — talks directly to authoritative servers)
(let ((resp (cl-dns:resolve-iterative "example.com" :a)))
  (format t "Authoritative: ~A~%"
          (= 1 (cl-dns::header-aa (cl-dns::message-header resp))))
  (dolist (rr (cl-dns::message-answers resp))
    (format t "~A~%" (cl-dns::rr-rdata rr))))

;; Useful for:
;; - Bypassing potentially-lying recursive resolvers
;; - Verifying authoritative data
;; - DNS debugging

;; With timeout
(cl-dns:resolve-iterative "deeply.nested.subdomain.example.com" :a :timeout 10)

;; Root server hints are configurable
cl-dns:*root-servers*
;; => (("a.root-servers.net" . "198.41.0.4") ...)
```
