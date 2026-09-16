(in-package #:cl-dns)

(defun mdns-query (name type &key (timeout 3))
  "Send an mDNS query on the local multicast group (224.0.0.251:5353)."
  (let* ((query (make-query name type :recursion-desired nil))
         (bytes (encode-message query))
         (socket (usocket:socket-connect nil nil
                   :protocol :datagram
                   :element-type '(unsigned-byte 8)
                   :timeout timeout
                   :local-port 5353)))
    (unwind-protect
        (progn
          (usocket:socket-send socket bytes (length bytes)
                              :host "224.0.0.251" :port 5353)
          (let ((buf (make-array 512 :element-type '(unsigned-byte 8))))
            (multiple-value-bind (recv n) (usocket:socket-receive socket buf 512)
              (declare (ignore recv))
              (when n (decode-message (subseq buf 0 n))))))
      (usocket:socket-close socket))))
(defun discover-services (service-type &key (timeout 3))
  "Discover services via DNS-SD (browse for _type._tcp.local)."
  (let* ((browse-name (format nil "~A.local" service-type))
         (resp (mdns-query browse-name :ptr :timeout timeout)))
    (when resp
      (mapcar (lambda (rr) (rr-rdata rr))
              (remove-if-not (lambda (rr) (eq (rr-type rr) :ptr))
                             (message-answers resp))))))
