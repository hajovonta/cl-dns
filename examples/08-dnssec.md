# DNSSEC Validation

```lisp
;; Validate a response's DNSSEC chain
(let* ((r (make-instance 'cl-dns:resolver))
       (resp (cl-dns:resolve r "example.com" :a))
       (store (make-instance 'cl-dns:trust-anchor-store)))
  (case (cl-dns:validate-dnssec r resp :trust-anchors store)
    (:secure   (format t "DNSSEC validated~%"))
    (:insecure (format t "No DNSSEC signatures present~%"))
    (:bogus    (format t "DNSSEC validation FAILED~%"))))

;; Add root trust anchors
(let ((store (make-instance 'cl-dns:trust-anchor-store)))
  (cl-dns:add-trust-anchor store "."
    '(:flags 257 :protocol 3 :algorithm 8
      :public-key #(...root-ksk-bytes...))))

;; Fetch and inspect DNSKEY records
(let* ((r (make-instance 'cl-dns:resolver))
       (resp (cl-dns:resolve r "example.com" :dnskey)))
  (dolist (rr (cl-dns::message-answers resp))
    (when (eq :dnskey (cl-dns::rr-type rr))
      (let ((key (cl-dns::rr-rdata rr)))
        (format t "Flags: ~D, Algo: ~D, Tag: ~D~%"
                (getf key :flags)
                (getf key :algorithm)
                (cl-dns::compute-key-tag key))))))

;; Verify authenticated denial of existence (NSEC)
(let ((nsec-records (message-authority resp)))
  (cl-dns:verify-denial "nonexistent.example.com" :a nsec-records))
```
