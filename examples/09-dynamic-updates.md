# Dynamic DNS Updates (RFC 2136)

```lisp
;; Add a record
(cl-dns:dns-update "ns1.example.com" "example.com"
  '((:op :add :name "new-host.example.com" :type :a :ttl 300 :rdata "10.0.0.5")))

;; Delete a record
(cl-dns:dns-update "ns1.example.com" "example.com"
  '((:op :delete :name "old-host.example.com" :type :a :rdata "10.0.0.99")))

;; Multiple operations in one update
(cl-dns:dns-update "ns1.example.com" "example.com"
  '((:op :delete :name "web.example.com" :type :a :rdata "10.0.0.1")
    (:op :add :name "web.example.com" :type :a :ttl 60 :rdata "10.0.0.2")
    (:op :add :name "web.example.com" :type :aaaa :ttl 60 :rdata "::1")))

;; Check response code
(multiple-value-bind (resp rcode)
    (cl-dns:dns-update "ns1.example.com" "example.com"
      '((:op :add :name "x.example.com" :type :a :ttl 300 :rdata "1.2.3.4")))
  (case rcode
    (0 (format t "Update successful~%"))
    (5 (format t "Update refused (check TSIG/permissions)~%"))
    (t (format t "Error: rcode ~D~%" rcode))))

;; With TSIG authentication (required by most nameservers)
(let* ((key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
       (msg (cl-dns::make-update-message "example.com"
              '((:op :add :name "x.example.com" :type :a :ttl 60 :rdata "1.2.3.4"))))
       (signed (cl-dns:tsig-sign msg "update-key" key)))
  ;; Include TSIG in the message before sending
  signed)
```
