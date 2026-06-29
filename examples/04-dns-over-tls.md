# DNS-over-TLS (DoT)

```lisp
;; Direct DoT query to Cloudflare
(let* ((query (cl-dns:make-query "example.com" :a))
       (bytes (cl-dns:encode-message query))
       (resp-bytes (cl-dns:dot-query "1.1.1.1" bytes)))
  (cl-dns:decode-message resp-bytes))

;; With connection pooling (reuses TLS connections)
(defvar *pool* (make-instance 'cl-dns:connection-pool :max-idle 4))

(let* ((query (cl-dns:make-query "github.com" :a))
       (bytes (cl-dns:encode-message query))
       ;; First call establishes TLS, subsequent calls reuse it
       (resp1 (cl-dns:dot-query "1.1.1.1" bytes :pool *pool*))
       (resp2 (cl-dns:dot-query "1.1.1.1" bytes :pool *pool*)))
  (values (cl-dns:decode-message resp1)
          (cl-dns:decode-message resp2)))

;; Clean up
(cl-dns:pool-close-all *pool*)

;; Using the transport abstraction
(let ((tr (make-instance 'cl-dns:tls-transport
            :host "1.1.1.1" :port 853 :pool *pool*))
      (bytes (cl-dns:encode-message (cl-dns:make-query "test.com" :a))))
  (cl-dns:send-query tr bytes :timeout 5))
```
