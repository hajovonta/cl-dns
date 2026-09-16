(in-package #:cl-dns)

(defun parse-ixfr-changes (answers)
  "Parse an IXFR answer section into a list of add/delete change operations.
The stream alternates SOA(old)/deletes/SOA(new)/adds; SOA records toggle the mode."
  (let ((changes nil)
        (mode nil))
    (dolist (rr answers)
      (cond
        ((eq :soa (rr-type rr))
         (setf mode (if (eq mode :delete) :add :delete)))
        ((eq mode :delete)
         (push (list :op :delete :rr rr) changes))
        ((eq mode :add)
         (push (list :op :add :rr rr) changes))))
    (nreverse changes)))
(defun make-update-message (zone updates)
  "Build a DNS UPDATE message (RFC 2136) from a zone and list of update operations.
Each update is a plist (:op :add/:delete, :name, :type, :ttl, :rdata)."
  (let ((msg (make-instance 'dns-message)))
    ;; Header: opcode=5 (UPDATE)
    (setf (header-opcode (message-header msg)) 5
          (header-qdcount (message-header msg)) 1)
    ;; Zone section (stored as question)
    (setf (message-questions msg)
          (list (make-instance 'dns-question :qname zone :qtype :soa :qclass :in)))
    ;; Update section (stored as authority)
    (let ((update-rrs nil))
      (dolist (u updates)
        (let ((op (getf u :op))
              (name (getf u :name))
              (type (getf u :type))
              (ttl (or (getf u :ttl) 0))
              (rdata (getf u :rdata)))
          (push (make-instance 'dns-rr
                  :name name :type type
                  :class (if (eq op :delete) :none :in)
                  :ttl ttl :rdata rdata)
                update-rrs)))
      (setf (message-authority msg) (nreverse update-rrs))
      (setf (header-nscount (message-header msg)) (length updates)))
    msg))
(defun zone-transfer (nameserver zone &key (timeout 30) (port 53))
  "Perform a full zone transfer (AXFR) from a nameserver. Returns list of RRs."
  (let* ((query (make-query zone :any))
         ;; AXFR uses QTYPE=252
         (axfr-type 252))
    ;; Override the qtype to AXFR (252)
    (setf (question-qtype (first (message-questions query))) axfr-type)
    (let* ((bytes (encode-message query))
           (socket (usocket:socket-connect nameserver port
                     :element-type '(unsigned-byte 8)
                     :timeout timeout))
           (records nil)
           (soa-count 0))
      (unwind-protect
          (let ((stream (usocket:socket-stream socket))
                (len (length bytes)))
            ;; Send with TCP length prefix
            (write-byte (ash len -8) stream)
            (write-byte (logand len #xFF) stream)
            (write-sequence bytes stream)
            (force-output stream)
            ;; Read responses until second SOA
            (loop
              (let* ((rlen (logior (ash (read-byte stream) 8) (read-byte stream)))
                     (buf (make-array rlen :element-type '(unsigned-byte 8))))
                (read-sequence buf stream)
                (let ((resp (decode-message buf)))
                  (dolist (rr (message-answers resp))
                    (push rr records)
                    (when (eq :soa (rr-type rr))
                      (incf soa-count)))
                  (when (>= soa-count 2)
                    (return))))))
        (usocket:socket-close socket))
      (nreverse records))))
(defun dns-update (nameserver zone updates &key (timeout 5) (port 53))
  "Send a dynamic DNS update (RFC 2136) to add/delete records."
  (let* ((msg (make-update-message zone updates))
         (bytes (encode-message msg))
         (resp-bytes (send-query-tcp nameserver bytes :timeout timeout :port port))
         (resp (decode-message resp-bytes)))
    (values resp (header-rcode (message-header resp)))))
(defun zone-transfer-incremental (nameserver zone serial &key (timeout 30) (port 53))
  "Perform an incremental zone transfer (IXFR) from a nameserver. Returns list of add/delete changes."
  (let* ((query (make-query zone :soa))
         ;; IXFR uses QTYPE=251, with current SOA serial in authority
         (ixfr-type 251)
         (current-soa (make-instance 'dns-rr
                        :name zone :type :soa :class :in :ttl 0
                        :rdata (list :serial serial))))
    (setf (question-qtype (first (message-questions query))) ixfr-type)
    (setf (message-authority query) (list current-soa)
          (header-nscount (message-header query)) 1)
    (let* ((bytes (encode-message query))
           (resp-bytes (send-query-tcp nameserver bytes :timeout timeout :port port))
           (resp (decode-message resp-bytes)))
      (parse-ixfr-changes (message-answers resp)))))
