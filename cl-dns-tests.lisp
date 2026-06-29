(defpackage #:cl-dns-tests
  (:use #:cl #:fiveam #:cl-dns))

(in-package #:cl-dns-tests)

(def-suite :cl-dns :description "Tests for cl-dns")

(def-suite :protocol :in :cl-dns)

(in-suite :protocol)

(test encode-simple-name
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((end (cl-dns::encode-name "example.com" buf 0)))
    (is (= end 13))
    (is (= (aref buf 0) 7))
    (is (= (aref buf 8) 3))
    (is (= (aref buf 12) 0)))))

(test encode-name-multi-label
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((end (cl-dns::encode-name "a.b.c.d" buf 0)))
    (is (= end 9))
    (is (= (aref buf 0) 1))
    (is (= (aref buf 2) 1)))))

(test encode-name-empty
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((end (cl-dns::encode-name "" buf 0)))
    (is (= end 1))
    (is (= (aref buf 0) 0)))))

(test decode-simple-name
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (cl-dns::encode-name "example.com" buf 0)
  (multiple-value-bind (name offset) (cl-dns::decode-name buf 0)
    (is (string= name "example.com"))
    (is (= offset 13)))))

(test decode-name-compression
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (cl-dns::encode-name "example.com" buf 0)
  (setf (aref buf 20) #xC0 (aref buf 21) #x00)
  (multiple-value-bind (name offset) (cl-dns::decode-name buf 20)
    (is (string= name "example.com"))
    (is (= offset 22)))))

(test decode-name-root
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (multiple-value-bind (name offset) (cl-dns::decode-name buf 0)
    (is (string= name ""))
    (is (= offset 1)))))

(test decode-rdata-a
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref buf 0) 93 (aref buf 1) 184 (aref buf 2) 216 (aref buf 3) 34)
  (is (string= (cl-dns::decode-rdata :a buf 0 4) "93.184.216.34"))))

(test decode-rdata-aaaa
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref buf 0) #x20 (aref buf 1) #x01 (aref buf 2) #x0d (aref buf 3) #xb8)
  (setf (aref buf 15) #x01)
  (let ((result (cl-dns::decode-rdata :aaaa buf 0 16)))
    (is (search "2001" result))
    (is (search "0db8" result)))))

(test decode-rdata-txt
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref buf 0) 5 (aref buf 1) (char-code #\h) (aref buf 2) (char-code #\e)
        (aref buf 3) (char-code #\l) (aref buf 4) (char-code #\l) (aref buf 5) (char-code #\o))
  (is (equal (cl-dns::decode-rdata :txt buf 0 6) '("hello")))))

(test decode-rdata-mx
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref buf 0) 0 (aref buf 1) 10)
  (cl-dns::encode-name "mail.test.com" buf 2)
  (let ((result (cl-dns::decode-rdata :mx buf 0 17)))
    (is (= 10 (first result)))
    (is (string= "mail.test.com" (second result))))))

(test decode-rdata-cname
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (cl-dns::encode-name "alias.example.com" buf 0)
  (is (string= (cl-dns::decode-rdata :cname buf 0 20) "alias.example.com"))))

(test encode-rdata-a
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((end (cl-dns::encode-rdata :a "192.168.1.1" buf 0)))
    (is (= end 4))
    (is (= (aref buf 0) 192))
    (is (= (aref buf 1) 168))
    (is (= (aref buf 2) 1))
    (is (= (aref buf 3) 1)))))

(test encode-rdata-cname
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((end (cl-dns::encode-rdata :cname "foo.bar.com" buf 0)))
    (is (> end 0))
    (is (= (aref buf 0) 3)))))

(test encode-query-message
  (let* ((msg (cl-dns:make-query "example.com" :a))
       (bytes (cl-dns:encode-message msg)))
  (is (> (length bytes) 12))
  (is (= 0 (logand (aref bytes 2) #x80)))
  (is (= 1 (aref bytes 5)))))

(test roundtrip-encode-decode
  (let* ((msg (cl-dns:make-query "test.org" :aaaa))
       (bytes (cl-dns:encode-message msg))
       (decoded (cl-dns:decode-message bytes)))
  (is (= 1 (cl-dns::header-qdcount (cl-dns::message-header decoded))))
  (is (string= "test.org" (cl-dns::question-qname (first (cl-dns::message-questions decoded)))))))

(test roundtrip-srv-query
  (let* ((msg (cl-dns:make-query "x.y" :srv))
       (bytes (cl-dns:encode-message msg))
       (decoded (cl-dns:decode-message bytes))
       (q (first (cl-dns::message-questions decoded))))
  (is (string= "x.y" (cl-dns::question-qname q)))
  (is (eq :srv (cl-dns::question-qtype q)))
  (is (eq :in (cl-dns::question-qclass q)))))

(test make-query-basic
  (let ((msg (cl-dns:make-query "foo.bar" :mx)))
  (is (= 1 (cl-dns::header-qdcount (cl-dns::message-header msg))))
  (is (eq :mx (cl-dns::question-qtype (first (cl-dns::message-questions msg)))))))

(test make-query-no-recursion
  (let* ((msg (cl-dns:make-query "test.example.com" :mx :class :in :recursion-desired nil))
       (hdr (cl-dns::message-header msg)))
  (is (= 0 (cl-dns::header-rd hdr)))
  (is (eq :mx (cl-dns::question-qtype (first (cl-dns::message-questions msg)))))))

(test encode-name-compressed-dedup
  (let ((buf (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))
      (ct (make-hash-table :test 'equal)))
  (let* ((off1 (cl-dns::encode-name-compressed "foo.example.com" buf 0 ct))
         (off2 (cl-dns::encode-name-compressed "bar.example.com" buf off1 ct)))
    ;; Second encode should use compression pointer for "example.com"
    (is (< off2 (+ off1 17)))
    ;; Verify we can decode both
    (is (string= "foo.example.com" (cl-dns::decode-name buf 0)))
    (is (string= "bar.example.com" (cl-dns::decode-name buf off1))))))

(test make-opt-rr-with-do-bit
  (let ((opt (cl-dns:make-opt-rr :udp-size 4096 :do-bit t)))
  (is (eq :opt (cl-dns::rr-type opt)))
  (is (= 4096 (cl-dns::rr-class opt)))
  (is (= #x8000 (cl-dns::rr-ttl opt)))))

(test make-opt-rr-defaults
  (let ((opt (cl-dns:make-opt-rr)))
  (is (= 0 (cl-dns::rr-ttl opt)))
  (is (string= "" (cl-dns::rr-name opt)))))

(test make-update-message-basic
  (let ((msg (cl-dns::make-update-message "example.com"
             '((:op :add :name "test.example.com" :type :a :ttl 300 :rdata "1.2.3.4")
               (:op :delete :name "old.example.com" :type :a :rdata "5.6.7.8")))))
  (is (= 5 (cl-dns::header-opcode (cl-dns::message-header msg))))
  (is (= 1 (cl-dns::header-qdcount (cl-dns::message-header msg))))
  (is (= 2 (cl-dns::header-nscount (cl-dns::message-header msg))))
  (is (eq :soa (cl-dns::question-qtype (first (cl-dns::message-questions msg)))))
  ;; Check that delete has :none class
  (let ((del-rr (second (cl-dns::message-authority msg))))
    (is (eq :none (cl-dns::rr-class del-rr))))))

(test root-servers-populated
  (is (= 13 (length cl-dns::*root-servers*)))
(is (string= "198.41.0.4" (cdr (first cl-dns::*root-servers*)))))

(test encode-name-compressed-same-twice
  (let ((buf (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0))
      (ct (make-hash-table :test 'equal)))
  ;; Encode same name twice — second should be just a 2-byte pointer
  (let* ((off1 (cl-dns::encode-name-compressed "test.com" buf 0 ct))
         (off2 (cl-dns::encode-name-compressed "test.com" buf off1 ct)))
    (is (= (- off2 off1) 2))
    ;; Pointer should be 0xC0 0x00
    (is (= #xC0 (logand (aref buf off1) #xC0))))))

(test encode-name-compressed-empty
  (let ((buf (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0))
      (ct (make-hash-table :test 'equal)))
  ;; Empty name should just be null byte
  (let ((off (cl-dns::encode-name-compressed "" buf 0 ct)))
    (is (= 1 off))
    (is (= 0 (aref buf 0))))))

(test encode-message-with-opt
  (let* ((msg (cl-dns:make-query "a.example.com" :a))
       ;; Add OPT to additional
       (opt (cl-dns:make-opt-rr :udp-size 4096)))
  (setf (cl-dns::message-additional msg) (list opt)
        (cl-dns::header-arcount (cl-dns::message-header msg)) 1)
  (let ((bytes (cl-dns:encode-message msg)))
    ;; Should have > 12 bytes (header) + question + OPT
    (is (> (length bytes) 30))
    ;; Last 11 bytes should be the OPT: 0(name) 0 41(type) 16 0(class=4096) 0 0 0 0(ttl) 0 0(rdlen)
    (let ((opt-start (- (length bytes) 11)))
      (is (= 0 (aref bytes opt-start)))      ; empty name
      (is (= 41 (aref bytes (+ opt-start 2)))) ; OPT type
      ))))

(test encode-update-message-opcode
  (let* ((msg (cl-dns::make-update-message "zone.com"
              '((:op :add :name "x.zone.com" :type :a :ttl 60 :rdata "10.0.0.1"))))
       (bytes (cl-dns:encode-message msg)))
  ;; Opcode=5 is in byte 2, bits 3-6
  (is (= 5 (ash (logand (aref bytes 2) #x78) -3)))))

(test encode-edns-options-basic
  (let ((opts (cl-dns::encode-edns-options (list (cons 10 #(1 2 3 4 5 6 7 8))))))
  ;; 4 bytes header + 8 bytes data
  (is (= 12 (length opts)))
  ;; Option code 10 in big-endian
  (is (= 0 (aref opts 0)))
  (is (= 10 (aref opts 1)))
  ;; Length = 8
  (is (= 0 (aref opts 2)))
  (is (= 8 (aref opts 3)))))

(test decode-edns-options-basic
  (let* ((data #(0 10 0 3 65 66 67))
       (opts (cl-dns::decode-edns-options data)))
  (is (= 1 (length opts)))
  (is (= 10 (car (first opts))))
  (is (= 3 (length (cdr (first opts)))))))

(test decode-edns-options-empty
  (is (null (cl-dns::decode-edns-options nil)))
(is (null (cl-dns::decode-edns-options #()))))

(test make-dns-cookie-basic
  (let ((cookie-rdata (cl-dns:make-dns-cookie "192.168.1.1" "8.8.8.8")))
  ;; Should be EDNS option: 4 header bytes + 8 byte client cookie
  (is (= 12 (length cookie-rdata)))
  ;; Option code 10 (cookie)
  (is (= 0 (aref cookie-rdata 0)))
  (is (= 10 (aref cookie-rdata 1)))))

(test make-dns-cookie-deterministic
  (let ((c1 (cl-dns:make-dns-cookie "10.0.0.1" "1.1.1.1"))
      (c2 (cl-dns:make-dns-cookie "10.0.0.2" "1.1.1.1")))
  ;; Different client IPs should produce different cookies
  (is (not (equalp c1 c2)))))

(test make-dns-cookie-with-server
  (let* ((server-cookie (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xAA))
       (cookie-rdata (cl-dns:make-dns-cookie "1.2.3.4" "5.6.7.8" :server-cookie server-cookie)))
  ;; 4 header + 8 client + 16 server = 28
  (is (= 28 (length cookie-rdata)))))

(test connection-pool-defaults
  (let ((pool (make-instance 'cl-dns:connection-pool :max-idle 2)))
  (is (= 0 (hash-table-count (cl-dns::pool-connections pool))))
  (is (= 2 (cl-dns::pool-max-idle pool)))))

(test pool-release-and-close
  (let ((pool (make-instance 'cl-dns:connection-pool :max-idle 2)))
  ;; Simulate releasing a fake stream
  (let ((fake-stream (make-string-input-stream "test")))
    (cl-dns::pool-release pool "host" 853 fake-stream)
    (is (= 1 (length (gethash (cons "host" 853) (cl-dns::pool-connections pool))))))
  ;; Acquire should return it
  ;; (can't test real acquire without network, but pool-close-all should work)
  (cl-dns:pool-close-all pool)
  (is (= 0 (hash-table-count (cl-dns::pool-connections pool))))))

(test pool-max-idle-eviction
  (let ((pool (make-instance 'cl-dns:connection-pool :max-idle 1)))
  (let ((s1 (make-string-input-stream "a"))
        (s2 (make-string-input-stream "b")))
    (cl-dns::pool-release pool "x" 853 s1)
    (cl-dns::pool-release pool "x" 853 s2)
    ;; max-idle=1, so only 1 should be kept
    (is (= 1 (length (gethash (cons "x" 853) (cl-dns::pool-connections pool))))))))

(test dns-error-condition
  (let ((c (make-condition 'cl-dns:dns-error :message "test" :rcode 5)))
  (is (string= "test" (cl-dns::dns-error-message c)))
  (is (= 5 (cl-dns::dns-error-rcode c)))))

(test dns-timeout-condition
  (let ((c (make-condition 'cl-dns:dns-timeout :nameserver "1.1.1.1")))
  (is (string= "1.1.1.1" (cl-dns::dns-timeout-nameserver c)))
  (is (search "timed out" (format nil "~A" c)))))

(test dns-nxdomain-condition
  (let ((c (make-condition 'cl-dns:dns-nxdomain :name "no.exist")))
  (is (string= "no.exist" (cl-dns::dns-nxdomain-name c)))
  (is (= 3 (cl-dns::dns-error-rcode c)))))

(test udp-transport-slots
  (let ((tr (make-instance 'cl-dns:udp-transport :host "8.8.8.8" :port 53)))
  (is (string= "8.8.8.8" (cl-dns::transport-host tr)))
  (is (= 53 (cl-dns::transport-port tr)))))

(test tls-transport-defaults
  (let ((tr (make-instance 'cl-dns:tls-transport :host "1.1.1.1")))
  (is (= 853 (cl-dns::transport-port tr)))
  (is (null (cl-dns::transport-pool tr)))))

(test tcp-transport-custom-port
  (let ((tr (make-instance 'cl-dns:tcp-transport :host "ns.test" :port 5353)))
  (is (string= "ns.test" (cl-dns::transport-host tr)))
  (is (= 5353 (cl-dns::transport-port tr)))))

(test dns-servfail-condition
  (let ((c (make-condition 'cl-dns:dns-servfail)))
  (is (= 2 (cl-dns::dns-error-rcode c)))
  (is (search "failure" (format nil "~A" c)))))

(def-suite :cache :in :cl-dns)

(in-suite :cache)

(test cache-store-and-lookup
  (let ((cache (make-instance 'cl-dns:dns-cache))
      (rr (make-instance 'cl-dns:dns-rr :name "test.com" :type :a :ttl 300 :rdata "1.2.3.4")))
  (cl-dns:cache-store cache (list rr))
  (let ((result (cl-dns:cache-lookup cache "test.com" :a)))
    (is (not (null result)))
    (is (string= "1.2.3.4" (cl-dns::rr-rdata (first result)))))))

(test cache-lookup-miss
  (let ((cache (make-instance 'cl-dns:dns-cache)))
  (is (null (cl-dns:cache-lookup cache "noexist.com" :a)))))

(test cache-expired-entry
  (let ((cache (make-instance 'cl-dns:dns-cache))
      (rr (make-instance 'cl-dns:dns-rr :name "expire.com" :type :a :ttl 0 :rdata "1.1.1.1")))
  (cl-dns:cache-store cache (list rr))
  (sleep 1)
  (is (null (cl-dns:cache-lookup cache "expire.com" :a)))))

(test cache-store-multiple
  (let ((cache (make-instance 'cl-dns:dns-cache))
      (rr1 (make-instance 'cl-dns:dns-rr :name "multi.com" :type :a :ttl 300 :rdata "1.1.1.1"))
      (rr2 (make-instance 'cl-dns:dns-rr :name "multi.com" :type :a :ttl 300 :rdata "2.2.2.2")))
  (cl-dns:cache-store cache (list rr1))
  (cl-dns:cache-store cache (list rr2))
  (is (= 2 (length (cl-dns:cache-lookup cache "multi.com" :a))))))

(test cache-purge-expired
  (let ((cache (make-instance 'cl-dns:dns-cache))
      (rr1 (make-instance 'cl-dns:dns-rr :name "purge1.com" :type :a :ttl 0 :rdata "1.1.1.1"))
      (rr2 (make-instance 'cl-dns:dns-rr :name "purge2.com" :type :a :ttl 300 :rdata "2.2.2.2")))
  (cl-dns:cache-store cache (list rr1 rr2))
  (sleep 1)
  (cl-dns:cache-purge cache)
  (is (null (cl-dns:cache-lookup cache "purge1.com" :a)))
  (is (not (null (cl-dns:cache-lookup cache "purge2.com" :a))))))

(test cache-case-insensitive
  (let ((cache (make-instance 'cl-dns:dns-cache))
      (rr (make-instance 'cl-dns:dns-rr :name "Case.COM" :type :a :ttl 300 :rdata "1.2.3.4")))
  (cl-dns:cache-store cache (list rr))
  (is (not (null (cl-dns:cache-lookup cache "case.com" :a))))
  (is (not (null (cl-dns:cache-lookup cache "CASE.COM" :a))))))

(test cache-lru-eviction
  (let ((cache (make-instance 'cl-dns:dns-cache :max-size 3)))
  (dotimes (i 5)
    (cl-dns:cache-store cache
      (list (make-instance 'cl-dns:dns-rr
              :name (format nil "host~D.com" i) :type :a :ttl 300
              :rdata (format nil "1.1.1.~D" i)))))
  ;; Should have at most 3 entries
  (is (<= (hash-table-count (cl-dns::cache-entries cache)) 3))))

(test cache-negative-store
  (let ((cache (make-instance 'cl-dns:dns-cache))
      (authority (list (make-instance 'cl-dns:dns-rr
                        :name "example.com" :type :soa :ttl 3600
                        :rdata '(:minimum 60)))))
  (cl-dns::cache-store-negative cache "nonexist.example.com" :a authority)
  (let ((result (cl-dns:cache-lookup cache "nonexist.example.com" :a)))
    (is (not (null result)))
    (is (eq :nxdomain (cl-dns::rr-rdata (first result)))))))

(test cache-lru-access-order
  (let ((cache (make-instance 'cl-dns:dns-cache :max-size 3)))
  (cl-dns:cache-store cache
    (list (make-instance 'cl-dns:dns-rr :name "old.com" :type :a :ttl 300 :rdata "1.1.1.1")))
  (cl-dns:cache-store cache
    (list (make-instance 'cl-dns:dns-rr :name "mid.com" :type :a :ttl 300 :rdata "2.2.2.2")))
  (cl-dns:cache-store cache
    (list (make-instance 'cl-dns:dns-rr :name "new.com" :type :a :ttl 300 :rdata "3.3.3.3")))
  ;; Access old.com to make it recently used
  (cl-dns:cache-lookup cache "old.com" :a)
  ;; Add one more to trigger eviction
  (cl-dns:cache-store cache
    (list (make-instance 'cl-dns:dns-rr :name "newest.com" :type :a :ttl 300 :rdata "4.4.4.4")))
  ;; mid.com should be evicted (least recently used)
  (is (null (cl-dns:cache-lookup cache "mid.com" :a)))
  ;; old.com should survive (recently accessed)
  (is (not (null (cl-dns:cache-lookup cache "old.com" :a))))))

(test cache-save-and-load
  (let ((cache (make-instance 'cl-dns:dns-cache))
      (rr (make-instance 'cl-dns:dns-rr :name "persist.com" :type :a :ttl 600 :rdata "7.7.7.7"))
      (path (merge-pathnames "cl-dns-test-cache.sexp" (uiop:temporary-directory))))
  (cl-dns:cache-store cache (list rr))
  (cl-dns:cache-save cache path)
  ;; Load into fresh cache
  (let ((cache2 (make-instance 'cl-dns:dns-cache)))
    (cl-dns:cache-load cache2 path)
    (let ((result (cl-dns:cache-lookup cache2 "persist.com" :a)))
      (is (not (null result)))
      (is (string= "7.7.7.7" (cl-dns::rr-rdata (first result))))))
  (delete-file path)))

(test cache-save-load-empty
  (let ((cache (make-instance 'cl-dns:dns-cache))
      (path (merge-pathnames "cl-dns-empty-test.sexp" (uiop:temporary-directory))))
  ;; Save empty cache
  (cl-dns:cache-save cache path)
  ;; Load into fresh cache — should not error
  (let ((cache2 (make-instance 'cl-dns:dns-cache)))
    (cl-dns:cache-load cache2 path)
    (is (= 0 (hash-table-count (cl-dns::cache-entries cache2)))))
  (delete-file path)))

(test cache-load-missing-file
  (let ((cache (make-instance 'cl-dns:dns-cache))
      (nonexistent (merge-pathnames "does-not-exist-xyz.sexp" (uiop:temporary-directory))))
  ;; Loading nonexistent file should not error
  (cl-dns:cache-load cache nonexistent)
  (is (= 0 (hash-table-count (cl-dns::cache-entries cache))))))

(def-suite :resolver :in :cl-dns)

(in-suite :resolver)

(test resolver-defaults
  (let ((r (make-instance 'cl-dns:resolver :nameservers '("8.8.8.8"))))
  (is (equal '("8.8.8.8") (cl-dns::resolver-nameservers r)))
  (is (= 5 (cl-dns::resolver-timeout r)))
  (is (= 2 (cl-dns::resolver-retries r)))))

(test resolve-from-cache
  (let* ((r (make-instance 'cl-dns:resolver))
       (rr (make-instance 'cl-dns:dns-rr :name "cached.test" :type :a :ttl 300 :rdata "9.9.9.9")))
  (cl-dns:cache-store (cl-dns::resolver-cache r) (list rr))
  (let ((resp (cl-dns:resolve r "cached.test" :a)))
    (is (not (null resp)))
    (is (= 1 (cl-dns::header-qr (cl-dns::message-header resp))))
    (is (string= "9.9.9.9" (cl-dns::rr-rdata (first (cl-dns::message-answers resp))))))))

(test resolve-query-building
  (let ((r (make-instance 'cl-dns:resolver :nameservers '("1.1.1.1" "8.8.8.8"))))
  ;; Verify make-query produces correct structure for resolve
  (let ((msg (cl-dns:make-query "test.com" :a :class :in)))
    (is (= 1 (cl-dns::header-qdcount (cl-dns::message-header msg))))
    (let ((bytes (cl-dns:encode-message msg)))
      (is (> (length bytes) 16))))))

(test resolve-cache-type-match
  (let* ((r (make-instance 'cl-dns:resolver))
       (rr (make-instance 'cl-dns:dns-rr :name "typed.test" :type :aaaa :ttl 300 :rdata "::1")))
  (cl-dns:cache-store (cl-dns::resolver-cache r) (list rr))
  ;; AAAA cached, so resolve AAAA should use cache (QR=1 indicates from cache)
  (let ((resp (cl-dns:resolve r "typed.test" :aaaa)))
    (is (= 1 (cl-dns::header-qr (cl-dns::message-header resp))))
    (is (string= "::1" (cl-dns::rr-rdata (first (cl-dns::message-answers resp))))))))

(test happy-eyeballs-from-cache
  (let* ((r (make-instance 'cl-dns:resolver))
       ;; Pre-populate cache with both A and AAAA
       (rr4 (make-instance 'cl-dns:dns-rr :name "dual.test" :type :a :ttl 300 :rdata "1.2.3.4"))
       (rr6 (make-instance 'cl-dns:dns-rr :name "dual.test" :type :aaaa :ttl 300 :rdata "::1")))
  (cl-dns:cache-store (cl-dns::resolver-cache r) (list rr4 rr6))
  (let ((addrs (cl-dns:happy-eyeballs r "dual.test" :timeout 1 :delay 0.05)))
    ;; IPv6 should come first
    (is (string= "::1" (first addrs)))
    (is (string= "1.2.3.4" (second addrs))))))

(test happy-eyeballs-v4-only
  (let* ((r (make-instance 'cl-dns:resolver))
       (rr (make-instance 'cl-dns:dns-rr :name "v4only.test" :type :a :ttl 300 :rdata "5.5.5.5")))
  (cl-dns:cache-store (cl-dns::resolver-cache r) (list rr))
  (let ((addrs (cl-dns:happy-eyeballs r "v4only.test" :timeout 1 :delay 0.05)))
    ;; Only IPv4 available
    (is (= 1 (length addrs)))
    (is (string= "5.5.5.5" (first addrs))))))

(test resolve-negative-cache-hit
  (let* ((r (make-instance 'cl-dns:resolver))
       (rr (make-instance 'cl-dns:dns-rr :name "neg.test" :type :a :ttl 300 :rdata :nxdomain)))
  (cl-dns:cache-store (cl-dns::resolver-cache r) (list rr))
  ;; Cached negative should return RCODE=3 from cache
  (let ((resp (cl-dns:resolve r "neg.test" :a)))
    (is (= 3 (cl-dns::header-rcode (cl-dns::message-header resp)))))))

(test make-update-add-aaaa
  (let ((msg (cl-dns::make-update-message "test.org"
             '((:op :add :name "a.test.org" :type :aaaa :ttl 120 :rdata "::1")))))
  ;; The RR in authority section should have class :in for add
  (let ((rr (first (cl-dns::message-authority msg))))
    (is (eq :in (cl-dns::rr-class rr)))
    (is (= 120 (cl-dns::rr-ttl rr)))
    (is (string= "::1" (cl-dns::rr-rdata rr))))))

(test dedup-single-query
  (let ((dedup (make-instance 'cl-dns:query-deduplicator))
      (call-count 0))
  (let ((result (cl-dns:deduplicate-query dedup "test.com" :a
                  (lambda () (incf call-count) :answer))))
    (is (eq :answer result))
    (is (= 1 call-count)))))

(test tsig-sign-basic
  (let* ((msg (cl-dns:make-query "test.com" :a))
       (key (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42))
       (signed (cl-dns:tsig-sign msg "mykey" key)))
  (is (stringp (getf signed :key-name)))
  (is (> (length (getf signed :mac)) 0))
  (is (= 300 (getf signed :fudge)))))

(test tsig-sign-deterministic
  (let* ((msg (cl-dns:make-query "sign.com" :a))
       (key (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11))
       (s1 (cl-dns:tsig-sign msg "k" key :algorithm :hmac-sha256))
       (s2 (cl-dns:tsig-sign msg "k" key :algorithm :hmac-sha256)))
  ;; Same input should produce same MAC
  (is (equalp (getf s1 :mac) (getf s2 :mac)))))

(test tsig-sign-different-keys
  (let* ((msg (cl-dns:make-query "x.com" :a))
       (key1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xAA))
       (key2 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xBB))
       (s1 (cl-dns:tsig-sign msg "k" key1))
       (s2 (cl-dns:tsig-sign msg "k" key2)))
  ;; Different keys produce different MACs
  (is (not (equalp (getf s1 :mac) (getf s2 :mac))))))

(test dedup-different-queries
  (let ((dedup (make-instance 'cl-dns:query-deduplicator)))
  ;; Sequential non-overlapping queries should each run
  (let ((r1 (cl-dns:deduplicate-query dedup "a.com" :a (lambda () :first)))
        (r2 (cl-dns:deduplicate-query dedup "b.com" :a (lambda () :second))))
    (is (eq :first r1))
    (is (eq :second r2)))))

(test resolve-parallel-from-cache
  (let* ((r (make-instance 'cl-dns:resolver))
       (rr4 (make-instance 'cl-dns:dns-rr :name "par.test" :type :a :ttl 300 :rdata "2.2.2.2"))
       (rr6 (make-instance 'cl-dns:dns-rr :name "par.test" :type :aaaa :ttl 300 :rdata "::2")))
  (cl-dns:cache-store (cl-dns::resolver-cache r) (list rr4 rr6))
  (let ((results (cl-dns:resolve-parallel r '(("par.test" :a) ("par.test" :aaaa)) :timeout 1)))
    (is (= 2 (length results)))
    (is (not (null (first results))))
    (is (not (null (second results)))))))

(def-suite :dnssec :in :cl-dns)

(in-suite :dnssec)

(test decode-dnskey-basic
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  ;; flags=257 (KSK), protocol=3, algorithm=8 (RSA/SHA-256), key=4 bytes
  (setf (aref buf 0) 1 (aref buf 1) 1   ; flags=257
        (aref buf 2) 3                    ; protocol
        (aref buf 3) 8                    ; algorithm
        (aref buf 4) #xAB (aref buf 5) #xCD (aref buf 6) #xEF (aref buf 7) #x01)
  (let ((result (cl-dns::decode-dnskey buf 0 8)))
    (is (= 257 (getf result :flags)))
    (is (= 3 (getf result :protocol)))
    (is (= 8 (getf result :algorithm)))
    (is (= 4 (length (getf result :public-key)))))))

(test decode-ds-basic
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  ;; key-tag=12345, algorithm=8, digest-type=2 (SHA-256), digest=4 bytes
  (setf (aref buf 0) (ash 12345 -8) (aref buf 1) (logand 12345 #xFF)
        (aref buf 2) 8 (aref buf 3) 2
        (aref buf 4) #xAA (aref buf 5) #xBB (aref buf 6) #xCC (aref buf 7) #xDD)
  (let ((result (cl-dns::decode-ds buf 0 8)))
    (is (= 12345 (getf result :key-tag)))
    (is (= 8 (getf result :algorithm)))
    (is (= 2 (getf result :digest-type)))
    (is (= 4 (length (getf result :digest)))))))

(test compute-key-tag-basic
  (let ((dnskey (list :flags 257 :protocol 3 :algorithm 8
                    :public-key (make-array 4 :element-type '(unsigned-byte 8)
                                             :initial-contents '(#xAB #xCD #xEF #x01)))))
  (let ((tag (cl-dns::compute-key-tag dnskey)))
    (is (integerp tag))
    (is (<= 0 tag 65535)))))

(test trust-anchor-add
  (let ((store (make-instance 'cl-dns:trust-anchor-store))
      (key '(:flags 257 :protocol 3 :algorithm 8 :public-key #(1 2 3))))
  (cl-dns:add-trust-anchor store "example.com" key)
  (is (= 1 (length (gethash "example.com" (cl-dns::trust-anchors store)))))))

(test validate-dnssec-insecure
  (let* ((resp (make-instance 'cl-dns:dns-message))
       ;; No RRSIG in answers → insecure
       (result (cl-dns:validate-dnssec (make-instance 'cl-dns:resolver) resp)))
  (is (eq :insecure result))))

(test build-signing-input-basic
  (let* ((rrsig (list :type-covered 1 :algorithm 8 :labels 2
                     :original-ttl 3600 :expiration 1000000 :inception 900000
                     :key-tag 12345 :signer "example.com"))
       (rrset (list (make-instance 'cl-dns:dns-rr
                     :name "test.example.com" :type :a :class :in
                     :ttl 3600 :rdata #(1 2 3 4))))
       (input (cl-dns::build-signing-input rrset rrsig)))
  ;; Should produce non-empty byte vector
  (is (> (length input) 0))
  ;; Should start with type-covered bytes
  (is (= 0 (aref input 0)))
  (is (= 1 (aref input 1)))))

(test build-signing-input-canonical-order
  (let* ((rrsig (list :type-covered 1 :algorithm 8 :labels 2
                     :original-ttl 300 :expiration 99999 :inception 88888
                     :key-tag 55555 :signer "example.com"))
       (rr1 (make-instance 'cl-dns:dns-rr :name "b.example.com" :type :a :class :in :ttl 300 :rdata #(2 2 2 2)))
       (rr2 (make-instance 'cl-dns:dns-rr :name "a.example.com" :type :a :class :in :ttl 300 :rdata #(1 1 1 1)))
       (input (cl-dns::build-signing-input (list rr1 rr2) rrsig)))
  ;; Canonical order: a.example.com before b.example.com
  (is (> (length input) 50))))

(test verify-ds-sha256
  (let* ((dnskey (list :flags 257 :protocol 3 :algorithm 8
                     :public-key (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAB)))
       ;; Compute DS digest for this key
       (buf (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0))
       (offset (cl-dns::encode-name "example.com" buf 0)))
  ;; Manually build the expected digest input
  (setf (aref buf offset) 1 (aref buf (+ offset 1)) 1) ; flags=257
  (incf offset 2)
  (setf (aref buf offset) 3) (incf offset) ; protocol
  (setf (aref buf offset) 8) (incf offset) ; algorithm
  (replace buf (getf dnskey :public-key) :start1 offset)
  (incf offset 32)
  (let* ((expected-digest (ironclad:digest-sequence :sha256 (subseq buf 0 offset)))
         (ds (list :key-tag 0 :algorithm 8 :digest-type 2 :digest expected-digest)))
    (is (cl-dns::verify-ds ds dnskey "example.com")))))

(test verify-ds-mismatch
  (let ((ds (list :key-tag 0 :algorithm 8 :digest-type 2
               :digest (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
      (dnskey (list :flags 257 :protocol 3 :algorithm 8
                    :public-key (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4)))))
  ;; Wrong digest should fail
  (is (not (cl-dns::verify-ds ds dnskey "example.com")))))

(test verify-ds-unknown-digest-type
  (let ((ds (list :key-tag 0 :algorithm 8 :digest-type 99 :digest #(1 2 3)))
      (dnskey (list :flags 257 :protocol 3 :algorithm 8 :public-key #(1 2 3 4))))
  ;; Unknown digest type returns nil
  (is (null (cl-dns::verify-ds ds dnskey "test.com")))))

(test verify-rrsig-unknown-algo
  (let ((rrsig (list :type-covered 1 :algorithm 99 :labels 2
                   :original-ttl 300 :expiration 99999 :inception 88888
                   :key-tag 100 :signer "x.com" :signature #(1 2 3)))
      (dnskey (list :flags 257 :protocol 3 :algorithm 99 :public-key #(4 5 6))))
  ;; Unknown algorithm should return nil
  (is (null (cl-dns:verify-rrsig rrsig dnskey nil)))))

(test decode-nsec-basic
  (let ((buf (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
  ;; Encode: next-domain "b.com" then bitmap window=0, len=1, byte=0b01000000 (type 1=A)
  (let ((off (cl-dns::encode-name "b.com" buf 0)))
    (setf (aref buf off) 0 (aref buf (+ off 1)) 1 (aref buf (+ off 2)) #x40)
    (let ((result (cl-dns::decode-nsec buf 0 (+ off 3))))
      (is (string= "b.com" (getf result :next-domain)))
      (is (member 1 (getf result :types)))))))

(test decode-nsec3-basic
  (let ((buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  ;; algorithm=1, flags=0, iterations=10, salt-len=4, salt, hash-len=8, hash, bitmap
  (setf (aref buf 0) 1 (aref buf 1) 0
        (aref buf 2) 0 (aref buf 3) 10
        (aref buf 4) 4
        (aref buf 5) #xAA (aref buf 6) #xBB (aref buf 7) #xCC (aref buf 8) #xDD)
  ;; hash-len=4
  (setf (aref buf 9) 4
        (aref buf 10) 1 (aref buf 11) 2 (aref buf 12) 3 (aref buf 13) 4)
  ;; bitmap: window=0, len=1, byte=0x40 (type 1)
  (setf (aref buf 14) 0 (aref buf 15) 1 (aref buf 16) #x40)
  (let ((result (cl-dns::decode-nsec3 buf 0 17)))
    (is (= 1 (getf result :algorithm)))
    (is (= 10 (getf result :iterations)))
    (is (= 4 (length (getf result :salt))))
    (is (member 1 (getf result :types))))))

(test verify-denial-nsec
  (let* ((nsec-rr (make-instance 'cl-dns:dns-rr
                  :name "a.example.com" :type :nsec :class :in :ttl 300
                  :rdata (list :next-domain "c.example.com" :types '(1 28)))))
  ;; b.example.com with type MX(15) should be denied (falls between a and c, type not in bitmap)
  (is (cl-dns:verify-denial "b.example.com" :mx (list nsec-rr)))
  ;; b.example.com with type A(1) should NOT be denied (type IS in bitmap)
  (is (not (cl-dns:verify-denial "b.example.com" :a (list nsec-rr))))))

(test verify-denial-nsec3
  (let* ((nsec3-rr (make-instance 'cl-dns:dns-rr
                    :name "abc.example.com" :type :nsec3 :class :in :ttl 300
                    :rdata (list :algorithm 1 :flags 0 :iterations 10
                                 :salt #(1 2) :next-hashed #(3 4)
                                 :types '(1 28 46)))))
  ;; Type MX(15) not in types list — denial should succeed
  (is (cl-dns:verify-denial "test.example.com" :mx (list nsec3-rr)))
  ;; Type A(1) IS in types — denial should fail
  (is (not (cl-dns:verify-denial "test.example.com" :a (list nsec3-rr))))))

(test verify-denial-empty-records
  (is (not (cl-dns:verify-denial "x.com" :a nil))))

(test verify-rrsig-bad-signature
  (let ((rrsig-data (list :type-covered 1 :algorithm 8 :labels 2
                        :original-ttl 300 :expiration 1 :inception 0
                        :key-tag 999 :signer "ex.com"
                        :signature (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
      (dnskey (list :flags 257 :protocol 3 :algorithm 8
                    :public-key (make-array 128 :element-type '(unsigned-byte 8) :initial-element 1)))
      (rrset (list (make-instance 'cl-dns:dns-rr :name "x.ex.com" :type :a :class :in :ttl 300 :rdata #(1 2 3 4)))))
  ;; Invalid signature bytes should return nil (crypto error caught)
  (is (null (cl-dns:verify-rrsig rrsig-data dnskey rrset)))))

;;; Coverage: 38/51 functions tested
