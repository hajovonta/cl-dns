# Error Handling (Conditions)

```lisp
;; cl-dns defines a condition hierarchy for structured error handling

;; Base condition
;; cl-dns:dns-error
;;   ├── cl-dns:dns-timeout    (query timed out)
;;   ├── cl-dns:dns-servfail   (rcode 2)
;;   └── cl-dns:dns-nxdomain   (rcode 3)

;; Signal conditions from your own code
(error 'cl-dns:dns-timeout :nameserver "8.8.8.8")
(error 'cl-dns:dns-nxdomain :name "nonexistent.com")
(error 'cl-dns:dns-servfail)

;; Handle them
(handler-case
    (let ((resp (cl-dns:resolve *resolver* "example.com" :a)))
      (when (= 3 (cl-dns::header-rcode (cl-dns::message-header resp)))
        (error 'cl-dns:dns-nxdomain :name "example.com"))
      resp)
  (cl-dns:dns-nxdomain (c)
    (format t "Name not found: ~A~%" (cl-dns::dns-nxdomain-name c)))
  (cl-dns:dns-timeout (c)
    (format t "Timeout querying ~A~%" (cl-dns::dns-timeout-nameserver c)))
  (cl-dns:dns-error (c)
    (format t "DNS error: ~A~%" c)))

;; Use with handler-bind for restarts
(handler-bind ((cl-dns:dns-timeout
                 (lambda (c)
                   (declare (ignore c))
                   (invoke-restart 'use-cached))))
  ;; ... resolution code ...
  )
```
