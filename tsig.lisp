(in-package #:cl-dns)

(defun tsig-variables-bytes (key-name time-signed)
  "Build the TSIG variables byte sequence (key name, class, TTL, time-signed, fudge) for MAC computation."
  (let* ((name-buf (make-array 96 :element-type '(unsigned-byte 8) :initial-element 0))
         (name-len (encode-name (string-downcase key-name) name-buf 0)))
    (coerce
     (append
      (coerce (subseq name-buf 0 name-len) 'list)
      (list 0 255)                 ; class ANY
      (list 0 0 0 0)               ; TTL = 0
      (list 0 0                    ; time-signed high 16 bits
            (logand (ash time-signed -24) #xFF)
            (logand (ash time-signed -16) #xFF)
            (logand (ash time-signed -8) #xFF)
            (logand time-signed #xFF))
      (list 1 44))                 ; fudge = 300
     '(vector (unsigned-byte 8)))))
(defun tsig-sign (message key-name key-data &key (algorithm :hmac-sha256))
  "Sign a DNS message with TSIG (RFC 8945) using HMAC via cl-crypto-util."
  (let* ((msg-bytes (encode-message message))
         (now (get-universal-time))
         (mac-name (case algorithm
                     (:hmac-sha256 :sha256)
                     (:hmac-sha512 :sha512)
                     (t :sha256)))
         (mac-input (concatenate '(vector (unsigned-byte 8))
                                 msg-bytes (tsig-variables-bytes key-name now))))
    (list :key-name key-name :algorithm algorithm
          :time-signed now :fudge 300
          :mac (cl-crypto-util:hmac-sign key-data mac-input :algorithm mac-name)
          :original-id (header-id (message-header message)))))
(defun tsig-verify (message key-name key-data)
  "Verify a TSIG signature on a DNS message using constant-time comparison."
  (let* ((tsig-rr (find :tsig (message-additional message) :key #'rr-type))
         (tsig-data (when tsig-rr (rr-rdata tsig-rr))))
    (unless tsig-data (return-from tsig-verify nil))
    (let* ((expected (tsig-sign message key-name key-data
                                :algorithm (or (getf tsig-data :algorithm) :hmac-sha256)))
           (expected-mac (getf expected :mac))
           (actual-mac (getf tsig-data :mac)))
      (and expected-mac actual-mac
           (cl-crypto-util:ct-equal expected-mac actual-mac)))))
