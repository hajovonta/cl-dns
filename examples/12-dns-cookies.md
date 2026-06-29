# DNS Cookies (RFC 7873)

```lisp
;; Generate a DNS cookie for anti-spoofing
(let ((cookie-option (cl-dns:make-dns-cookie "192.168.1.100" "8.8.8.8")))
  ;; cookie-option is EDNS0 option data ready to include in OPT record
  (format t "Cookie option: ~D bytes~%" (length cookie-option)))

;; Include server cookie from a previous response
(let ((server-cookie #(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
  (cl-dns:make-dns-cookie "10.0.0.1" "1.1.1.1" :server-cookie server-cookie))

;; EDNS0 options encoding/decoding
(let* ((opts (cl-dns::encode-edns-options
               (list (cons 10 #(1 2 3 4 5 6 7 8))   ; cookie
                     (cons 3 #(0 0)))))               ; NSID
       (decoded (cl-dns::decode-edns-options opts)))
  (format t "~D options decoded~%" (length decoded)))
```
