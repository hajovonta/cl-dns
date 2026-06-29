(in-package #:cl-dns)

(defun validate-dnssec (resolver response &key trust-anchors)
  "Validate the full DNSSEC chain for a response. Returns :secure, :insecure, or :bogus."
  (let* ((answers (message-answers response))
         (rrsigs (remove-if-not (lambda (rr) (eq :rrsig (rr-type rr))) answers))
         (store (or trust-anchors (make-instance 'trust-anchor-store))))
    (unless rrsigs
      (return-from validate-dnssec :insecure))
    ;; For each RRSIG, find the matching DNSKEY and verify
    (dolist (sig-rr rrsigs)
      (let* ((sig-data (rr-rdata sig-rr))
             (signer (getf sig-data :signer))
             (key-tag (getf sig-data :key-tag))
             (type-covered (getf sig-data :type-covered))
             ;; Find the RRset that was signed
             (type-kw (or (car (rassoc type-covered *record-types*)) type-covered))
             (rrset (remove-if-not (lambda (rr)
                                     (and (eq type-kw (rr-type rr))
                                          (not (eq :rrsig (rr-type rr)))))
                                   answers)))
        ;; Fetch DNSKEY for the signer zone
        (let* ((key-resp (resolve resolver signer :dnskey))
               (dnskeys (when key-resp
                          (remove-if-not (lambda (rr) (eq :dnskey (rr-type rr)))
                                         (message-answers key-resp))))
               ;; Find matching key by tag
               (matching-key (find-if (lambda (rr)
                                        (let ((kd (rr-rdata rr)))
                                          (= key-tag (compute-key-tag kd))))
                                      dnskeys)))
          (unless matching-key
            (return-from validate-dnssec :bogus))
          ;; Check trust: is this key in trust anchors or validated via DS?
          (let* ((kdata (rr-rdata matching-key))
                 (anchors (gethash (string-downcase signer) (trust-anchors store)))
                 (trusted (find-if (lambda (a) (= (compute-key-tag a) key-tag)) anchors)))
            (unless trusted
              ;; Try DS validation from parent
              (let* ((parent (subseq signer (1+ (or (position #\. signer) 0))))
                     (ds-resp (resolve resolver signer :ds))
                     (ds-records (when ds-resp
                                   (remove-if-not (lambda (rr) (eq :ds (rr-type rr)))
                                                  (message-answers ds-resp)))))
                (unless (some (lambda (ds-rr)
                                (verify-ds (rr-rdata ds-rr) kdata signer))
                              ds-records)
                  (declare (ignore parent))
                  (return-from validate-dnssec :bogus))))
            ;; Verify the signature
            (unless (verify-rrsig sig-data kdata rrset)
              (return-from validate-dnssec :bogus))))))
    :secure))
(defun add-trust-anchor (store zone dnskey-rdata)
  "Add a trust anchor (DNSKEY) for a zone."
  (push dnskey-rdata (gethash (string-downcase zone) (trust-anchors store))))
(defclass trust-anchor-store ()
  ((anchors :initform (make-hash-table :test 'equal) :accessor trust-anchors))
  (:documentation "Trust anchor store mapping zone names to trusted DNSKEY records."))
(defun verify-ds (ds-record dnskey owner-name)
  "Verify DS record matches a DNSKEY by computing the digest."
  (let* ((digest-type (getf ds-record :digest-type))
         (expected (getf ds-record :digest))
         (digest-name (case digest-type
                        (1 :sha1)
                        (2 :sha256)
                        (4 :sha384)
                        (t (return-from verify-ds nil))))
         ;; Input: canonical owner name wire format + DNSKEY RDATA
         (buf (make-array 1024 :element-type '(unsigned-byte 8) :initial-element 0))
         (offset (encode-name (string-downcase owner-name) buf 0))
         (flags (getf dnskey :flags))
         (protocol (getf dnskey :protocol))
         (algorithm (getf dnskey :algorithm))
         (pubkey (getf dnskey :public-key)))
    ;; Append DNSKEY RDATA: flags(2) + protocol(1) + algorithm(1) + public key
    (setf (aref buf offset) (ash flags -8)
          (aref buf (+ offset 1)) (logand flags #xFF))
    (incf offset 2)
    (setf (aref buf offset) protocol) (incf offset)
    (setf (aref buf offset) algorithm) (incf offset)
    (replace buf pubkey :start1 offset)
    (incf offset (length pubkey))
    ;; Compute digest
    (let ((computed (ironclad:digest-sequence digest-name (subseq buf 0 offset))))
      (equalp computed expected))))
(defun verify-rrsig (rrsig dnskey rrset)
  "Validate an RRSIG signature against a DNSKEY and RRset. Returns T if valid."
  (let* ((rrsig-data (if (listp rrsig) rrsig (decode-rrsig rrsig 0 (length rrsig))))
         (algorithm (getf rrsig-data :algorithm))
         (signature (getf rrsig-data :signature))
         (pubkey-bytes (getf dnskey :public-key))
         (signing-input (build-signing-input rrset rrsig-data))
         (digest-name (case algorithm
                        ((5 7) :sha1)     ; RSA/SHA-1, RSA/SHA-1 NSEC3
                        (8 :sha256)        ; RSA/SHA-256
                        (10 :sha512)       ; RSA/SHA-512
                        (13 :sha256)       ; ECDSA P-256/SHA-256
                        (14 :sha384)       ; ECDSA P-384/SHA-384
                        (t (return-from verify-rrsig nil)))))
    (handler-case
        (case algorithm
          ((5 7 8 10)
           ;; RSA verification
           (let ((pubkey (ironclad:make-public-key :rsa
                           :n (ironclad:octets-to-integer pubkey-bytes)
                           :e #x10001)))
             (ironclad:verify-signature pubkey signing-input signature
                                        :pss nil :digest-name digest-name)))
          ((13 14)
           ;; ECDSA - key is raw x||y coordinates
           (let* ((key-size (if (= algorithm 13) 32 48))
                  (x (subseq pubkey-bytes 0 key-size))
                  (y (subseq pubkey-bytes key-size)))
             (let ((pubkey (ironclad:make-public-key
                            (if (= algorithm 13) :secp256r1 :secp384r1)
                            :x (ironclad:octets-to-integer x)
                            :y (ironclad:octets-to-integer y))))
               (ironclad:verify-signature pubkey signing-input signature
                                          :digest-name digest-name))))
          (t nil))
      (error () nil))))
(defun build-signing-input (rrset rrsig)
  "Build the canonical wire-format RRset for signature verification (RFC 4034 sec 6.3)."
  (let ((buf (make-array 4096 :element-type '(unsigned-byte 8) :initial-element 0))
        (offset 0))
    ;; RRSIG RDATA fields (without signature)
    (let ((tc (getf rrsig :type-covered))
          (alg (getf rrsig :algorithm))
          (labels (getf rrsig :labels))
          (ottl (getf rrsig :original-ttl))
          (exp (getf rrsig :expiration))
          (inc (getf rrsig :inception))
          (kt (getf rrsig :key-tag))
          (signer (getf rrsig :signer)))
      (setf (aref buf 0) (ash tc -8) (aref buf 1) (logand tc #xFF)) (incf offset 2)
      (setf (aref buf offset) alg) (incf offset)
      (setf (aref buf offset) labels) (incf offset)
      (setf (aref buf offset) (ash ottl -24)
            (aref buf (+ offset 1)) (logand (ash ottl -16) #xFF)
            (aref buf (+ offset 2)) (logand (ash ottl -8) #xFF)
            (aref buf (+ offset 3)) (logand ottl #xFF))
      (incf offset 4)
      (setf (aref buf offset) (ash exp -24)
            (aref buf (+ offset 1)) (logand (ash exp -16) #xFF)
            (aref buf (+ offset 2)) (logand (ash exp -8) #xFF)
            (aref buf (+ offset 3)) (logand exp #xFF))
      (incf offset 4)
      (setf (aref buf offset) (ash inc -24)
            (aref buf (+ offset 1)) (logand (ash inc -16) #xFF)
            (aref buf (+ offset 2)) (logand (ash inc -8) #xFF)
            (aref buf (+ offset 3)) (logand inc #xFF))
      (incf offset 4)
      (setf (aref buf offset) (ash kt -8) (aref buf (+ offset 1)) (logand kt #xFF))
      (incf offset 2)
      ;; Signer name in canonical wire format (lowercase)
      (setf offset (encode-name (string-downcase signer) buf offset)))
    ;; Append each RR in canonical order
    (dolist (rr (sort (copy-list rrset) #'string< :key (lambda (r) (string-downcase (rr-name r)))))
      ;; owner name (lowercase)
      (setf offset (encode-name (string-downcase (rr-name rr)) buf offset))
      ;; type
      (let ((rt (or (cdr (assoc (rr-type rr) *record-types*)) 0)))
        (setf (aref buf offset) (ash rt -8) (aref buf (+ offset 1)) (logand rt #xFF)))
      (incf offset 2)
      ;; class
      (let ((rc (or (cdr (assoc (rr-class rr) *class-codes*)) 1)))
        (setf (aref buf offset) (ash rc -8) (aref buf (+ offset 1)) (logand rc #xFF)))
      (incf offset 2)
      ;; original TTL from RRSIG
      (let ((ottl (getf rrsig :original-ttl)))
        (setf (aref buf offset) (ash ottl -24)
              (aref buf (+ offset 1)) (logand (ash ottl -16) #xFF)
              (aref buf (+ offset 2)) (logand (ash ottl -8) #xFF)
              (aref buf (+ offset 3)) (logand ottl #xFF)))
      (incf offset 4)
      ;; RDATA length + RDATA (encode raw)
      (let* ((rdata (rr-rdata rr))
             (rdlen (if (typep rdata 'sequence) (length rdata) 0)))
        (setf (aref buf offset) (ash rdlen -8) (aref buf (+ offset 1)) (logand rdlen #xFF))
        (incf offset 2)
        (when (and (typep rdata 'sequence) (> rdlen 0))
          (replace buf rdata :start1 offset)
          (incf offset rdlen))))
    (subseq buf 0 offset)))
(defun compute-key-tag (dnskey-rdata)
  "Compute the key tag for a DNSKEY record (RFC 4034 appendix B)."
  (let* ((flags (getf dnskey-rdata :flags))
         (protocol (getf dnskey-rdata :protocol))
         (algorithm (getf dnskey-rdata :algorithm))
         (key (getf dnskey-rdata :public-key))
         (acc 0))
    ;; flags (2 bytes) + protocol (1) + algorithm (1) + public key
    (incf acc (+ (ash flags 0)))
    (incf acc (+ (ash protocol 8) algorithm))
    (loop for i from 0 below (length key)
          do (incf acc (if (evenp i)
                           (ash (aref key i) 8)
                           (aref key i))))
    (logand (+ (logand acc #xFFFF) (ash acc -16)) #xFFFF)))
(defun decode-ds (buffer offset rdlength)
  "Parse DS RDATA into a structured plist (key-tag, algorithm, digest-type, digest)."
  (list :key-tag (logior (ash (aref buffer offset) 8) (aref buffer (+ offset 1)))
        :algorithm (aref buffer (+ offset 2))
        :digest-type (aref buffer (+ offset 3))
        :digest (subseq buffer (+ offset 4) (+ offset rdlength))))
(defun decode-dnskey (buffer offset rdlength)
  "Parse DNSKEY RDATA into a structured plist (flags, protocol, algorithm, public-key)."
  (list :flags (logior (ash (aref buffer offset) 8) (aref buffer (+ offset 1)))
        :protocol (aref buffer (+ offset 2))
        :algorithm (aref buffer (+ offset 3))
        :public-key (subseq buffer (+ offset 4) (+ offset rdlength))))
(defun decode-rrsig (buffer offset rdlength)
  "Parse RRSIG RDATA into a structured plist."
  (let* ((type-covered (logior (ash (aref buffer offset) 8) (aref buffer (+ offset 1))))
         (algorithm (aref buffer (+ offset 2)))
         (labels (aref buffer (+ offset 3)))
         (original-ttl (logior (ash (aref buffer (+ offset 4)) 24)
                               (ash (aref buffer (+ offset 5)) 16)
                               (ash (aref buffer (+ offset 6)) 8)
                               (aref buffer (+ offset 7))))
         (expiration (logior (ash (aref buffer (+ offset 8)) 24)
                             (ash (aref buffer (+ offset 9)) 16)
                             (ash (aref buffer (+ offset 10)) 8)
                             (aref buffer (+ offset 11))))
         (inception (logior (ash (aref buffer (+ offset 12)) 24)
                            (ash (aref buffer (+ offset 13)) 16)
                            (ash (aref buffer (+ offset 14)) 8)
                            (aref buffer (+ offset 15))))
         (key-tag (logior (ash (aref buffer (+ offset 16)) 8)
                          (aref buffer (+ offset 17))))
         (signer-start (+ offset 18)))
    (multiple-value-bind (signer signer-end) (decode-name buffer signer-start)
      (list :type-covered type-covered
            :algorithm algorithm
            :labels labels
            :original-ttl original-ttl
            :expiration expiration
            :inception inception
            :key-tag key-tag
            :signer signer
            :signature (subseq buffer signer-end (+ offset rdlength))))))
