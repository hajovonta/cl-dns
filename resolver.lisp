(in-package #:cl-dns)

(defun resolve (resolver name type &key (class :in) (timeout 5) (retries 2))
  "Resolve a DNS query. Returns a dns-message with the response. Checks cache first."
  (let ((cached (cache-lookup (resolver-cache resolver) name type)))
    (when cached
      (if (eq :nxdomain (rr-rdata (first cached)))
          (let ((msg (make-instance 'dns-message)))
            (setf (header-qr (message-header msg)) 1
                  (header-rcode (message-header msg)) 3)
            (return-from resolve msg))
          (let ((msg (make-instance 'dns-message)))
            (setf (header-qr (message-header msg)) 1)
            (setf (message-answers msg) cached)
            (return-from resolve msg)))))
  (let* ((query (make-query name type :class class))
         ;; Add EDNS0 OPT record
         (opt (make-opt-rr))
         (_ (progn (setf (message-additional query) (list opt))
                   (setf (header-arcount (message-header query)) 1)))
         (bytes (encode-message query))
         (ns-list (resolver-nameservers resolver)))
    (declare (ignore _))
    (loop for attempt from 0 below (1+ retries)
          for ns = (nth (mod attempt (length ns-list)) ns-list)
          do (handler-case
                 (let* ((resp-bytes (send-query-udp ns bytes :timeout timeout))
                        (resp (decode-message resp-bytes)))
                   ;; Retry via TCP if truncated
                   (when (= 1 (header-tc (message-header resp)))
                     (setf resp-bytes (send-query-tcp ns bytes :timeout timeout)
                           resp (decode-message resp-bytes)))
                   ;; Cache positive or negative
                   (if (= 3 (header-rcode (message-header resp)))
                       (cache-store-negative (resolver-cache resolver) name type
                                             (message-authority resp))
                       (cache-store (resolver-cache resolver) (message-answers resp)))
                   (return resp))
               (error () nil)))))
(defun send-query-tcp (nameserver query-bytes &key (timeout 5) (port 53))
  "Send a raw DNS query over TCP to the nameserver (for large responses)."
  (let ((socket (usocket:socket-connect nameserver port
                  :element-type '(unsigned-byte 8)
                  :timeout timeout)))
    (unwind-protect
        (let ((stream (usocket:socket-stream socket))
              (len (length query-bytes)))
          ;; TCP DNS: 2-byte length prefix
          (write-byte (ash len -8) stream)
          (write-byte (logand len #xFF) stream)
          (write-sequence query-bytes stream)
          (force-output stream)
          ;; Read response length
          (let* ((rlen (logior (ash (read-byte stream) 8) (read-byte stream)))
                 (buf (make-array rlen :element-type '(unsigned-byte 8))))
            (read-sequence buf stream)
            buf))
      (usocket:socket-close socket))))
(defun send-query-udp (nameserver query-bytes &key (timeout 5) (port 53))
  "Send a raw DNS query over UDP to the nameserver and return the response bytes."
  (let ((socket (usocket:socket-connect nameserver port
                  :protocol :datagram
                  :element-type '(unsigned-byte 8)
                  :timeout timeout)))
    (unwind-protect
        (progn
          (usocket:socket-send socket query-bytes (length query-bytes))
          (let ((buf (make-array 512 :element-type '(unsigned-byte 8))))
            (multiple-value-bind (recv n) (usocket:socket-receive socket buf 512)
              (declare (ignore recv))
              (subseq buf 0 n))))
      (usocket:socket-close socket))))
(defun make-query (name type &key (class :in) (recursion-desired t))
  "Build a DNS query message for the given name and type."
  (let ((msg (make-instance 'dns-message)))
    (setf (header-rd (message-header msg)) (if recursion-desired 1 0))
    (setf (header-qdcount (message-header msg)) 1)
    (setf (message-questions msg)
          (list (make-instance 'dns-question :qname name :qtype type :qclass class)))
    msg))
(defclass resolver ()
  ((nameservers :initarg :nameservers :accessor resolver-nameservers
                :initform '("8.8.8.8" "8.8.4.4"))
   (cache :initarg :cache :accessor resolver-cache
          :initform (make-instance 'dns-cache))
   (timeout :initarg :timeout :accessor resolver-timeout :initform 5)
   (retries :initarg :retries :accessor resolver-retries :initform 2))
  (:documentation "Async DNS resolver with caching, configurable nameservers, timeout and retry."))

(defun resolve-parallel (resolver queries &key (timeout 5))
  "Resolve multiple queries concurrently using threads. Returns list of responses."
  (let* ((n (length queries))
         (results (make-array n :initial-element nil))
         (threads
           (loop for (name type) in queries
                 for i from 0
                 collect (let ((idx i) (qname name) (qtype type))
                           (bt:make-thread
                            (lambda ()
                              (setf (aref results idx)
                                    (resolve resolver qname qtype :timeout timeout)))
                            :name (format nil "dns-resolve-~D" idx))))))
    (dolist (th threads)
      (bt:join-thread th))
    (coerce results 'list)))

(defun happy-eyeballs (resolver name &key (timeout 5) (delay 0.25))
  "Resolve a hostname using Happy Eyeballs (RFC 8305): parallel A+AAAA with IPv6 preference and fallback.
Returns a sorted list of addresses (IPv6 first, then IPv4)."
  (let ((v6-result nil) (v4-result nil)
        (v6-done nil) (v4-done nil)
        (lock (bt:make-lock "happy-eyeballs")))
    ;; Launch both queries
    (let ((v6-thread (bt:make-thread
                      (lambda ()
                        (let ((resp (resolve resolver name :aaaa :timeout timeout)))
                          (bt:with-lock-held (lock)
                            (setf v6-result (when resp
                                              (mapcar #'rr-rdata
                                                      (remove-if-not (lambda (rr) (eq :aaaa (rr-type rr)))
                                                                     (message-answers resp))))
                                  v6-done t))))
                      :name "happy-v6"))
          (v4-thread (bt:make-thread
                      (lambda ()
                        ;; RFC 8305: delay IPv4 slightly to prefer IPv6
                        (sleep delay)
                        (let ((resp (resolve resolver name :a :timeout timeout)))
                          (bt:with-lock-held (lock)
                            (setf v4-result (when resp
                                              (mapcar #'rr-rdata
                                                      (remove-if-not (lambda (rr) (eq :a (rr-type rr)))
                                                                     (message-answers resp))))
                                  v4-done t))))
                      :name "happy-v4")))
      (bt:join-thread v6-thread)
      (bt:join-thread v4-thread))
    ;; Return IPv6 addresses first (preferred), then IPv4
    (append v6-result v4-result)))
