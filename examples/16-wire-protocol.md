# Wire Protocol (Low-Level)

```lisp
;; Build a raw DNS query manually
(let* ((msg (make-instance 'cl-dns:dns-message))
       (hdr (cl-dns::message-header msg)))
  ;; Set header flags
  (setf (cl-dns::header-rd hdr) 1          ; recursion desired
        (cl-dns::header-qdcount hdr) 1)
  ;; Add question
  (setf (cl-dns::message-questions msg)
        (list (make-instance 'cl-dns:dns-question
                :qname "example.com" :qtype :a :qclass :in)))
  ;; Add EDNS0 OPT
  (let ((opt (cl-dns:make-opt-rr :udp-size 4096 :do-bit t)))
    (setf (cl-dns::message-additional msg) (list opt)
          (cl-dns::header-arcount hdr) 1))
  ;; Encode to bytes
  (cl-dns:encode-message msg))

;; Decode a raw DNS response
(let ((resp (cl-dns:decode-message response-bytes)))
  (format t "ID: ~D, QR: ~D, RCODE: ~D~%"
          (cl-dns::header-id (cl-dns::message-header resp))
          (cl-dns::header-qr (cl-dns::message-header resp))
          (cl-dns::header-rcode (cl-dns::message-header resp)))
  (format t "Questions: ~D, Answers: ~D~%"
          (length (cl-dns::message-questions resp))
          (length (cl-dns::message-answers resp))))

;; Name encoding with compression
(let ((buf (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0))
      (table (make-hash-table :test 'equal)))
  ;; First name: fully encoded
  (cl-dns::encode-name-compressed "mail.example.com" buf 0 table)
  ;; Second name: "example.com" suffix compressed via pointer
  (cl-dns::encode-name-compressed "www.example.com" buf 18 table))

;; Record type constants
cl-dns:*record-types*
;; => ((:A . 1) (:NS . 2) (:CNAME . 5) ... (:RRSIG . 46) (:DNSKEY . 48))
```
