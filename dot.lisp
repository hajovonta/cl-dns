(in-package #:cl-dns)

(defun dot-query (nameserver query-bytes &key (timeout 5) (port 853) pool)
  "Send a DNS query via DNS-over-TLS (RFC 7858). Optionally reuses connections from POOL."
  (declare (ignore timeout))
  (let* ((stream (if pool
                     (pool-acquire pool nameserver port :tls t)
                     (let ((tcp-socket (usocket:socket-connect nameserver port
                                         :element-type '(unsigned-byte 8)
                                         :timeout 10)))
                       (cl+ssl:make-ssl-client-stream
                        (usocket:socket-stream tcp-socket)
                        :hostname nameserver))))
         (len (length query-bytes)))
    (handler-case
        (progn
          (write-byte (ash len -8) stream)
          (write-byte (logand len #xFF) stream)
          (write-sequence query-bytes stream)
          (force-output stream)
          (let* ((rlen (logior (ash (read-byte stream) 8) (read-byte stream)))
                 (buf (make-array rlen :element-type '(unsigned-byte 8))))
            (read-sequence buf stream)
            (when pool (pool-release pool nameserver port stream))
            buf))
      (error (c)
        (ignore-errors (close stream))
        (error c)))))
