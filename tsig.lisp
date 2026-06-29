(in-package #:cl-dns)

(defun tsig-verify (message key-name key-data)
  "Verify a TSIG signature on a DNS message."
  (let* ((tsig-rr (find :tsig (message-additional message) :key #'rr-type))
         (tsig-data (when tsig-rr (rr-rdata tsig-rr))))
    (unless tsig-data (return-from tsig-verify nil))
    ;; Recompute and compare
    (let* ((expected (tsig-sign message key-name key-data
                                :algorithm (or (getf tsig-data :algorithm) :hmac-sha256)))
           (expected-mac (getf expected :mac))
           (actual-mac (getf tsig-data :mac)))
      (and expected-mac actual-mac (equalp expected-mac actual-mac)))))
(defun tsig-sign (message key-name key-data &key (algorithm :hmac-sha256))
  "Sign a DNS message with TSIG (RFC 2845) using HMAC."
  (let* ((msg-bytes (encode-message message))
         (now (get-universal-time))
         (mac-name (case algorithm
                     (:hmac-sha256 :sha256)
                     (:hmac-sha512 :sha512)
                     (:hmac-sha1 :sha1)
                     (t :sha256)))
         (tsig-vars (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))
         (tv-off 0))
    ;; Key name in wire format
    (setf tv-off (encode-name (string-downcase key-name) tsig-vars 0))
    ;; Class ANY = 255
    (setf (aref tsig-vars tv-off) 0 (aref tsig-vars (+ tv-off 1)) 255) (incf tv-off 2)
    ;; TTL = 0
    (incf tv-off 4)
    ;; Time signed (48 bits — use low 32)
    (setf (aref tsig-vars tv-off) 0 (aref tsig-vars (+ tv-off 1)) 0) (incf tv-off 2)
    (setf (aref tsig-vars tv-off) (logand (ash now -24) #xFF)
          (aref tsig-vars (+ tv-off 1)) (logand (ash now -16) #xFF)
          (aref tsig-vars (+ tv-off 2)) (logand (ash now -8) #xFF)
          (aref tsig-vars (+ tv-off 3)) (logand now #xFF))
    (incf tv-off 4)
    ;; Fudge = 300
    (setf (aref tsig-vars tv-off) 1 (aref tsig-vars (+ tv-off 1)) 44) (incf tv-off 2)
    ;; Compute MAC
    (let* ((input (concatenate '(vector (unsigned-byte 8))
                               msg-bytes (subseq tsig-vars 0 tv-off)))
           (mac (ironclad:make-mac :hmac key-data mac-name))
           (signature (progn (ironclad:update-mac mac input)
                             (ironclad:produce-mac mac))))
      (list :key-name key-name :algorithm algorithm
            :time-signed now :fudge 300
            :mac signature :original-id (header-id (message-header message))))))
