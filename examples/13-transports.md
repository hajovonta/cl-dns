# Pluggable Transports

```lisp
;; The transport abstraction allows swapping protocols without changing logic

;; UDP (default, fast, 512-byte limit without EDNS0)
(let ((tr (make-instance 'cl-dns:udp-transport :host "8.8.8.8" :port 53))
      (bytes (cl-dns:encode-message (cl-dns:make-query "example.com" :a))))
  (cl-dns:send-query tr bytes :timeout 3))

;; TCP (for large responses, zone transfers)
(let ((tr (make-instance 'cl-dns:tcp-transport :host "8.8.8.8" :port 53))
      (bytes (cl-dns:encode-message (cl-dns:make-query "example.com" :any))))
  (cl-dns:send-query tr bytes :timeout 5))

;; TLS (encrypted, with optional connection pooling)
(let* ((pool (make-instance 'cl-dns:connection-pool :max-idle 4))
       (tr (make-instance 'cl-dns:tls-transport
             :host "1.1.1.1" :port 853 :pool pool))
       (bytes (cl-dns:encode-message (cl-dns:make-query "example.com" :a))))
  (cl-dns:send-query tr bytes :timeout 5)
  ;; Connection is returned to pool for reuse
  (cl-dns:send-query tr bytes :timeout 5)
  ;; Clean up
  (cl-dns:pool-close-all pool))

;; Mock transport for testing (user-defined)
;; (defclass mock-transport () ((responses :initarg :responses)))
;; (defmethod cl-dns:send-query ((tr mock-transport) bytes &key timeout) ...)
```
