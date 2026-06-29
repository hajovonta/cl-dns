# TSIG Authentication

```lisp
;; Sign a message with HMAC-SHA256
(let* ((msg (cl-dns:make-query "example.com" :a))
       (key-name "my-update-key")
       (key-data (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element 0)) ; replace with real key
       (tsig (cl-dns:tsig-sign msg key-name key-data)))
  (format t "Key: ~A~%Algorithm: ~A~%MAC length: ~D~%"
          (getf tsig :key-name)
          (getf tsig :algorithm)
          (length (getf tsig :mac))))

;; Different algorithms
(cl-dns:tsig-sign msg "key" key-data :algorithm :hmac-sha512)
(cl-dns:tsig-sign msg "key" key-data :algorithm :hmac-sha1)

;; Verify a TSIG on a received message
;; (message must have TSIG RR in additional section)
(cl-dns:tsig-verify response "shared-key" key-data)
;; => T or NIL
```
