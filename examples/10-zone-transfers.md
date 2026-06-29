# Zone Transfers

```lisp
;; Full zone transfer (AXFR)
(let ((records (cl-dns:zone-transfer "ns1.example.com" "example.com")))
  (format t "Got ~D records~%" (length records))
  (dolist (rr records)
    (format t "~A ~A ~A~%"
            (cl-dns::rr-name rr) (cl-dns::rr-type rr) (cl-dns::rr-rdata rr))))

;; With custom timeout for large zones
(cl-dns:zone-transfer "ns1.example.com" "example.com" :timeout 120)

;; Incremental zone transfer (IXFR)
;; Only get changes since serial 2024010100
(let ((changes (cl-dns:zone-transfer-incremental
                "ns1.example.com" "example.com" 2024010100)))
  (dolist (change changes)
    (format t "~A: ~A ~A~%"
            (getf change :op)
            (cl-dns::rr-type (getf change :rr))
            (cl-dns::rr-name (getf change :rr)))))
```
