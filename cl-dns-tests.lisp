(defpackage #:cl-dns-tests
  (:use #:cl #:fiveam #:cl-dns))

(in-package #:cl-dns-tests)

(def-suite :cl-dns :description "Tests for cl-dns")

(def-suite :protocol :in :cl-dns)

(in-suite :protocol)

(test encode-simple-name
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((cl-dns-tests::end
         (cl-dns:encode-name "example.com" cl-dns-tests::buf 0)))
    (is (= cl-dns-tests::end 13))
    (is (= (aref cl-dns-tests::buf 0) 7))
    (is (= (aref cl-dns-tests::buf 8) 3))
    (is (= (aref cl-dns-tests::buf 12) 0))))
)

(test encode-name-multi-label
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((cl-dns-tests::end (cl-dns:encode-name "a.b.c.d" cl-dns-tests::buf 0)))
    (is (= cl-dns-tests::end 9))
    (is (= (aref cl-dns-tests::buf 0) 1))
    (is (= (aref cl-dns-tests::buf 2) 1))))
)

(test encode-name-empty
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((cl-dns-tests::end (cl-dns:encode-name "" cl-dns-tests::buf 0)))
    (is (= cl-dns-tests::end 1))
    (is (= (aref cl-dns-tests::buf 0) 0))))
)

(test decode-simple-name
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (cl-dns:encode-name "example.com" cl-dns-tests::buf 0)
  (multiple-value-bind (cl-dns-tests::name cl-dns-tests::offset)
      (cl-dns:decode-name cl-dns-tests::buf 0)
    (is (string= cl-dns-tests::name "example.com"))
    (is (= cl-dns-tests::offset 13))))
)

(test decode-name-compression
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (cl-dns:encode-name "example.com" cl-dns-tests::buf 0)
  (setf (aref cl-dns-tests::buf 20) 192
        (aref cl-dns-tests::buf 21) 0)
  (multiple-value-bind (cl-dns-tests::name cl-dns-tests::offset)
      (cl-dns:decode-name cl-dns-tests::buf 20)
    (is (string= cl-dns-tests::name "example.com"))
    (is (= cl-dns-tests::offset 22))))
)

(test decode-name-root
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (multiple-value-bind (cl-dns-tests::name cl-dns-tests::offset)
      (cl-dns:decode-name cl-dns-tests::buf 0)
    (is (string= cl-dns-tests::name ""))
    (is (= cl-dns-tests::offset 1))))
)

(test decode-rdata-a
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref cl-dns-tests::buf 0) 93
        (aref cl-dns-tests::buf 1) 184
        (aref cl-dns-tests::buf 2) 216
        (aref cl-dns-tests::buf 3) 34)
  (is
   (string= (cl-dns::decode-rdata :a cl-dns-tests::buf 0 4) "93.184.216.34")))
)

(test decode-rdata-aaaa
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref cl-dns-tests::buf 0) 32
        (aref cl-dns-tests::buf 1) 1
        (aref cl-dns-tests::buf 2) 13
        (aref cl-dns-tests::buf 3) 184)
  (setf (aref cl-dns-tests::buf 15) 1)
  (let ((cl-dns-tests::result
         (cl-dns::decode-rdata :aaaa cl-dns-tests::buf 0 16)))
    (is (search "2001" cl-dns-tests::result))
    (is (search "0db8" cl-dns-tests::result))))
)

(test decode-rdata-txt
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref cl-dns-tests::buf 0) 5
        (aref cl-dns-tests::buf 1) (char-code #\h)
        (aref cl-dns-tests::buf 2) (char-code #\e)
        (aref cl-dns-tests::buf 3) (char-code #\l)
        (aref cl-dns-tests::buf 4) (char-code #\l)
        (aref cl-dns-tests::buf 5) (char-code #\o))
  (is (equal (cl-dns::decode-rdata :txt cl-dns-tests::buf 0 6) '("hello"))))
)

(test decode-rdata-mx
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref cl-dns-tests::buf 0) 0
        (aref cl-dns-tests::buf 1) 10)
  (cl-dns:encode-name "mail.test.com" cl-dns-tests::buf 2)
  (let ((cl-dns-tests::result
         (cl-dns::decode-rdata :mx cl-dns-tests::buf 0 17)))
    (is (= 10 (first cl-dns-tests::result)))
    (is (string= "mail.test.com" (second cl-dns-tests::result)))))
)

(test decode-rdata-cname
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (cl-dns:encode-name "alias.example.com" cl-dns-tests::buf 0)
  (is
   (string= (cl-dns::decode-rdata :cname cl-dns-tests::buf 0 20)
            "alias.example.com")))
)

(test encode-rdata-a
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((cl-dns-tests::end
         (cl-dns::encode-rdata :a "192.168.1.1" cl-dns-tests::buf 0)))
    (is (= cl-dns-tests::end 4))
    (is (= (aref cl-dns-tests::buf 0) 192))
    (is (= (aref cl-dns-tests::buf 1) 168))
    (is (= (aref cl-dns-tests::buf 2) 1))
    (is (= (aref cl-dns-tests::buf 3) 1))))
)

(test encode-rdata-cname
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((cl-dns-tests::end
         (cl-dns::encode-rdata :cname "foo.bar.com" cl-dns-tests::buf 0)))
    (is (> cl-dns-tests::end 0))
    (is (= (aref cl-dns-tests::buf 0) 3))))
)

(test encode-query-message
  (let* ((cl-dns-tests::msg (cl-dns:make-query "example.com" :a))
       (cl-dns-tests::bytes (cl-dns:encode-message cl-dns-tests::msg)))
  (is (> (length cl-dns-tests::bytes) 12))
  (is (= 0 (logand (aref cl-dns-tests::bytes 2) 128)))
  (is (= 1 (aref cl-dns-tests::bytes 5))))
)

(test roundtrip-encode-decode
  (let* ((cl-dns-tests::msg (cl-dns:make-query "test.org" :aaaa))
       (cl-dns-tests::bytes (cl-dns:encode-message cl-dns-tests::msg))
       (cl-dns-tests::decoded (cl-dns:decode-message cl-dns-tests::bytes)))
  (is
   (= 1
      (cl-dns::header-qdcount (cl-dns::message-header cl-dns-tests::decoded))))
  (is
   (string= "test.org"
            (cl-dns::question-qname
             (first (cl-dns::message-questions cl-dns-tests::decoded))))))
)

(test roundtrip-srv-query
  (let* ((cl-dns-tests::msg (cl-dns:make-query "x.y" :srv))
       (cl-dns-tests::bytes (cl-dns:encode-message cl-dns-tests::msg))
       (cl-dns-tests::decoded (cl-dns:decode-message cl-dns-tests::bytes))
       (cl-dns-tests::q
        (first (cl-dns::message-questions cl-dns-tests::decoded))))
  (is (string= "x.y" (cl-dns::question-qname cl-dns-tests::q)))
  (is (eq :srv (cl-dns::question-qtype cl-dns-tests::q)))
  (is (eq :in (cl-dns::question-qclass cl-dns-tests::q))))
)

(test make-query-basic
  (let ((cl-dns-tests::msg (cl-dns:make-query "foo.bar" :mx)))
  (is
   (= 1 (cl-dns::header-qdcount (cl-dns::message-header cl-dns-tests::msg))))
  (is
   (eq :mx
       (cl-dns::question-qtype
        (first (cl-dns::message-questions cl-dns-tests::msg))))))
)

(test make-query-no-recursion
  (let* ((cl-dns-tests::msg
        (cl-dns:make-query "test.example.com" :mx :class :in :recursion-desired
                           nil))
       (cl-dns-tests::hdr (cl-dns::message-header cl-dns-tests::msg)))
  (is (= 0 (cl-dns::header-rd cl-dns-tests::hdr)))
  (is
   (eq :mx
       (cl-dns::question-qtype
        (first (cl-dns::message-questions cl-dns-tests::msg))))))
)

(test encode-name-compressed-dedup
  (let ((cl-dns-tests::buf
       (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0))
      (cl-dns-tests::ct (make-hash-table :test 'equal)))
  (let* ((cl-dns-tests::off1
          (cl-dns::encode-name-compressed "foo.example.com" cl-dns-tests::buf 0
                                          cl-dns-tests::ct))
         (cl-dns-tests::off2
          (cl-dns::encode-name-compressed "bar.example.com" cl-dns-tests::buf
                                          cl-dns-tests::off1 cl-dns-tests::ct)))
    (is (< cl-dns-tests::off2 (+ cl-dns-tests::off1 17)))
    (is (string= "foo.example.com" (cl-dns:decode-name cl-dns-tests::buf 0)))
    (is
     (string= "bar.example.com"
              (cl-dns:decode-name cl-dns-tests::buf cl-dns-tests::off1)))))
)

(test make-opt-rr-with-do-bit
  (let ((cl-dns-tests::opt (cl-dns:make-opt-rr :udp-size 4096 :do-bit t)))
  (is (eq :opt (cl-dns::rr-type cl-dns-tests::opt)))
  (is (= 4096 (cl-dns::rr-class cl-dns-tests::opt)))
  (is (= 32768 (cl-dns::rr-ttl cl-dns-tests::opt))))
)

(test make-opt-rr-defaults
  (let ((cl-dns-tests::opt (cl-dns:make-opt-rr)))
  (is (= 0 (cl-dns::rr-ttl cl-dns-tests::opt)))
  (is (string= "" (cl-dns::rr-name cl-dns-tests::opt))))
)

(test make-update-message-basic
  (let ((cl-dns-tests::msg
       (cl-dns::make-update-message "example.com"
                                    '((:op :add :name "test.example.com" :type
                                       :a :ttl 300 :rdata "1.2.3.4")
                                      (:op :delete :name "old.example.com"
                                       :type :a :rdata "5.6.7.8")))))
  (is (= 5 (cl-dns::header-opcode (cl-dns::message-header cl-dns-tests::msg))))
  (is
   (= 1 (cl-dns::header-qdcount (cl-dns::message-header cl-dns-tests::msg))))
  (is
   (= 2 (cl-dns::header-nscount (cl-dns::message-header cl-dns-tests::msg))))
  (is
   (eq :soa
       (cl-dns::question-qtype
        (first (cl-dns::message-questions cl-dns-tests::msg)))))
  (let ((cl-dns-tests::del-rr
         (second (cl-dns::message-authority cl-dns-tests::msg))))
    (is (eq :none (cl-dns::rr-class cl-dns-tests::del-rr)))))
)

(test encode-name-compressed-same-twice
  (let ((cl-dns-tests::buf
       (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0))
      (cl-dns-tests::ct (make-hash-table :test 'equal)))
  (let* ((cl-dns-tests::off1
          (cl-dns::encode-name-compressed "test.com" cl-dns-tests::buf 0
                                          cl-dns-tests::ct))
         (cl-dns-tests::off2
          (cl-dns::encode-name-compressed "test.com" cl-dns-tests::buf
                                          cl-dns-tests::off1 cl-dns-tests::ct)))
    (is (= (- cl-dns-tests::off2 cl-dns-tests::off1) 2))
    (is (= 192 (logand (aref cl-dns-tests::buf cl-dns-tests::off1) 192)))))
)

(test encode-name-compressed-empty
  (let ((cl-dns-tests::buf
       (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0))
      (cl-dns-tests::ct (make-hash-table :test 'equal)))
  (let ((cl-dns-tests::off
         (cl-dns::encode-name-compressed "" cl-dns-tests::buf 0
                                         cl-dns-tests::ct)))
    (is (= 1 cl-dns-tests::off))
    (is (= 0 (aref cl-dns-tests::buf 0)))))
)

(test encode-message-with-opt
  (let* ((cl-dns-tests::msg (cl-dns:make-query "a.example.com" :a))
       (cl-dns-tests::opt (cl-dns:make-opt-rr :udp-size 4096)))
  (setf (cl-dns::message-additional cl-dns-tests::msg) (list cl-dns-tests::opt)
        (cl-dns::header-arcount (cl-dns::message-header cl-dns-tests::msg)) 1)
  (let ((cl-dns-tests::bytes (cl-dns:encode-message cl-dns-tests::msg)))
    (is (> (length cl-dns-tests::bytes) 30))
    (let ((cl-dns-tests::opt-start (- (length cl-dns-tests::bytes) 11)))
      (is (= 0 (aref cl-dns-tests::bytes cl-dns-tests::opt-start)))
      (is (= 41 (aref cl-dns-tests::bytes (+ cl-dns-tests::opt-start 2)))))))
)

(test encode-update-message-opcode
  (let* ((cl-dns-tests::msg
        (cl-dns::make-update-message "zone.com"
                                     '((:op :add :name "x.zone.com" :type :a
                                        :ttl 60 :rdata "10.0.0.1"))))
       (cl-dns-tests::bytes (cl-dns:encode-message cl-dns-tests::msg)))
  (is (= 5 (ash (logand (aref cl-dns-tests::bytes 2) 120) -3))))
)

(test encode-edns-options-basic
  (let ((cl-dns-tests::opts
       (cl-dns::encode-edns-options (list (cons 10 #(1 2 3 4 5 6 7 8))))))
  (is (= 12 (length cl-dns-tests::opts)))
  (is (= 0 (aref cl-dns-tests::opts 0)))
  (is (= 10 (aref cl-dns-tests::opts 1)))
  (is (= 0 (aref cl-dns-tests::opts 2)))
  (is (= 8 (aref cl-dns-tests::opts 3))))
)

(test decode-edns-options-basic
  (let* ((cl-dns-tests::data #(0 10 0 3 65 66 67))
       (cl-dns-tests::opts (cl-dns::decode-edns-options cl-dns-tests::data)))
  (is (= 1 (length cl-dns-tests::opts)))
  (is (= 10 (car (first cl-dns-tests::opts))))
  (is (= 3 (length (cdr (first cl-dns-tests::opts))))))
)

(test decode-edns-options-empty
  (is (null (cl-dns::decode-edns-options nil)))
(is (null (cl-dns::decode-edns-options #())))
)

(test make-dns-cookie-basic
  (let ((cl-dns-tests::cookie-rdata
       (cl-dns:make-dns-cookie "192.168.1.1" "8.8.8.8")))
  (is (= 12 (length cl-dns-tests::cookie-rdata)))
  (is (= 0 (aref cl-dns-tests::cookie-rdata 0)))
  (is (= 10 (aref cl-dns-tests::cookie-rdata 1))))
)

(test make-dns-cookie-deterministic
  (let ((cl-dns-tests::c1 (cl-dns:make-dns-cookie "10.0.0.1" "1.1.1.1"))
      (cl-dns-tests::c2 (cl-dns:make-dns-cookie "10.0.0.2" "1.1.1.1")))
  (is (not (equalp cl-dns-tests::c1 cl-dns-tests::c2))))
)

(test make-dns-cookie-with-server
  (let* ((cl-dns-tests::server-cookie
        (make-array 16 :element-type '(unsigned-byte 8) :initial-element 170))
       (cl-dns-tests::cookie-rdata
        (cl-dns:make-dns-cookie "1.2.3.4" "5.6.7.8" :server-cookie
                                cl-dns-tests::server-cookie)))
  (is (= 28 (length cl-dns-tests::cookie-rdata))))
)

(test connection-pool-defaults
  (let ((cl-dns-tests::pool (make-instance 'cl-dns:connection-pool :max-idle 2)))
  (is (= 0 (hash-table-count (cl-dns::pool-connections cl-dns-tests::pool))))
  (is (= 2 (cl-dns::pool-max-idle cl-dns-tests::pool))))
)

(test pool-release-and-close
  (let ((cl-dns-tests::pool (make-instance 'cl-dns:connection-pool :max-idle 2)))
  (let ((cl-dns-tests::fake-stream (make-string-input-stream "test")))
    (cl-dns::pool-release cl-dns-tests::pool "host" 853
                          cl-dns-tests::fake-stream)
    (is
     (= 1
        (length
         (gethash (cons "host" 853)
                  (cl-dns::pool-connections cl-dns-tests::pool))))))
  (cl-dns:pool-close-all cl-dns-tests::pool)
  (is (= 0 (hash-table-count (cl-dns::pool-connections cl-dns-tests::pool)))))
)

(test pool-max-idle-eviction
  (let ((cl-dns-tests::pool (make-instance 'cl-dns:connection-pool :max-idle 1)))
  (let ((cl-dns-tests::s1 (make-string-input-stream "a"))
        (cl-dns-tests::s2 (make-string-input-stream "b")))
    (cl-dns::pool-release cl-dns-tests::pool "x" 853 cl-dns-tests::s1)
    (cl-dns::pool-release cl-dns-tests::pool "x" 853 cl-dns-tests::s2)
    (is
     (= 1
        (length
         (gethash (cons "x" 853)
                  (cl-dns::pool-connections cl-dns-tests::pool)))))))
)

(test dns-error-condition
  (let ((cl-dns-tests::c
       (make-condition 'cl-dns:dns-error :message "test" :rcode 5)))
  (is (string= "test" (cl-dns::dns-error-message cl-dns-tests::c)))
  (is (= 5 (cl-dns::dns-error-rcode cl-dns-tests::c))))
)

(test dns-timeout-condition
  (let ((cl-dns-tests::c
       (make-condition 'cl-dns:dns-timeout :nameserver "1.1.1.1")))
  (is (string= "1.1.1.1" (cl-dns::dns-timeout-nameserver cl-dns-tests::c)))
  (is (search "timed out" (format nil "~A" cl-dns-tests::c))))
)

(test dns-nxdomain-condition
  (let ((cl-dns-tests::c (make-condition 'cl-dns:dns-nxdomain :name "no.exist")))
  (is (string= "no.exist" (cl-dns::dns-nxdomain-name cl-dns-tests::c)))
  (is (= 3 (cl-dns::dns-error-rcode cl-dns-tests::c))))
)

(test udp-transport-slots
  (let ((cl-dns-tests::tr
       (make-instance 'cl-dns:udp-transport :host "8.8.8.8" :port 53)))
  (is (string= "8.8.8.8" (cl-dns::transport-host cl-dns-tests::tr)))
  (is (= 53 (cl-dns::transport-port cl-dns-tests::tr))))
)

(test tls-transport-defaults
  (let ((cl-dns-tests::tr (make-instance 'cl-dns:tls-transport :host "1.1.1.1")))
  (is (= 853 (cl-dns::transport-port cl-dns-tests::tr)))
  (is (null (cl-dns::transport-pool cl-dns-tests::tr))))
)

(test tcp-transport-custom-port
  (let ((cl-dns-tests::tr
       (make-instance 'cl-dns:tcp-transport :host "ns.test" :port 5353)))
  (is (string= "ns.test" (cl-dns::transport-host cl-dns-tests::tr)))
  (is (= 5353 (cl-dns::transport-port cl-dns-tests::tr))))
)

(test dns-servfail-condition
  (let ((cl-dns-tests::c (make-condition 'cl-dns:dns-servfail)))
  (is (= 2 (cl-dns::dns-error-rcode cl-dns-tests::c)))
  (is (search "failure" (format nil "~A" cl-dns-tests::c))))
)

(test root-servers-populated
  (is (= 13 (length cl-dns::*root-servers*)))
(is (string= "198.41.0.4" (cdr (first cl-dns::*root-servers*))))
)

(def-suite :cache :in :cl-dns)

(in-suite :cache)

(test cache-store-and-lookup
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache))
      (cl-dns-tests::rr
       (make-instance 'cl-dns:dns-rr :name "test.com" :type :a :ttl 300 :rdata
                      "1.2.3.4")))
  (cl-dns:cache-store cl-dns-tests::cache (list cl-dns-tests::rr))
  (let ((cl-dns-tests::result
         (cl-dns:cache-lookup cl-dns-tests::cache "test.com" :a)))
    (is (not (null cl-dns-tests::result)))
    (is (string= "1.2.3.4" (cl-dns::rr-rdata (first cl-dns-tests::result))))))
)

(test cache-lookup-miss
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache)))
  (is (null (cl-dns:cache-lookup cl-dns-tests::cache "noexist.com" :a))))
)

(test cache-expired-entry
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache))
      (cl-dns-tests::rr
       (make-instance 'cl-dns:dns-rr :name "expire.com" :type :a :ttl 0 :rdata
                      "1.1.1.1")))
  (cl-dns:cache-store cl-dns-tests::cache (list cl-dns-tests::rr))
  (sleep 1)
  (is (null (cl-dns:cache-lookup cl-dns-tests::cache "expire.com" :a))))
)

(test cache-store-multiple
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache))
      (cl-dns-tests::rr1
       (make-instance 'cl-dns:dns-rr :name "multi.com" :type :a :ttl 300 :rdata
                      "1.1.1.1"))
      (cl-dns-tests::rr2
       (make-instance 'cl-dns:dns-rr :name "multi.com" :type :a :ttl 300 :rdata
                      "2.2.2.2")))
  (cl-dns:cache-store cl-dns-tests::cache (list cl-dns-tests::rr1))
  (cl-dns:cache-store cl-dns-tests::cache (list cl-dns-tests::rr2))
  (is (= 2 (length (cl-dns:cache-lookup cl-dns-tests::cache "multi.com" :a)))))
)

(test cache-purge-expired
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache))
      (cl-dns-tests::rr1
       (make-instance 'cl-dns:dns-rr :name "purge1.com" :type :a :ttl 0 :rdata
                      "1.1.1.1"))
      (cl-dns-tests::rr2
       (make-instance 'cl-dns:dns-rr :name "purge2.com" :type :a :ttl 300
                      :rdata "2.2.2.2")))
  (cl-dns:cache-store cl-dns-tests::cache
                      (list cl-dns-tests::rr1 cl-dns-tests::rr2))
  (sleep 1)
  (cl-dns:cache-purge cl-dns-tests::cache)
  (is (null (cl-dns:cache-lookup cl-dns-tests::cache "purge1.com" :a)))
  (is (not (null (cl-dns:cache-lookup cl-dns-tests::cache "purge2.com" :a)))))
)

(test cache-case-insensitive
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache))
      (cl-dns-tests::rr
       (make-instance 'cl-dns:dns-rr :name "Case.COM" :type :a :ttl 300 :rdata
                      "1.2.3.4")))
  (cl-dns:cache-store cl-dns-tests::cache (list cl-dns-tests::rr))
  (is (not (null (cl-dns:cache-lookup cl-dns-tests::cache "case.com" :a))))
  (is (not (null (cl-dns:cache-lookup cl-dns-tests::cache "CASE.COM" :a)))))
)

(test cache-lru-eviction
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache :max-size 3)))
  (dotimes (cl-dns-tests::i 5)
    (cl-dns:cache-store cl-dns-tests::cache
                        (list
                         (make-instance 'cl-dns:dns-rr :name
                                        (format nil "host~D.com"
                                                cl-dns-tests::i)
                                        :type :a :ttl 300 :rdata
                                        (format nil "1.1.1.~D"
                                                cl-dns-tests::i)))))
  (is (<= (hash-table-count (cl-dns::cache-entries cl-dns-tests::cache)) 3)))
)

(test cache-negative-store
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache))
      (cl-dns-tests::authority
       (list
        (make-instance 'cl-dns:dns-rr :name "example.com" :type :soa :ttl 3600
                       :rdata '(:minimum 60)))))
  (cl-dns::cache-store-negative cl-dns-tests::cache "nonexist.example.com" :a
                                cl-dns-tests::authority)
  (let ((cl-dns-tests::result
         (cl-dns:cache-lookup cl-dns-tests::cache "nonexist.example.com" :a)))
    (is (not (null cl-dns-tests::result)))
    (is (eq :nxdomain (cl-dns::rr-rdata (first cl-dns-tests::result))))))
)

(test cache-lru-access-order
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache :max-size 3)))
  (cl-dns:cache-store cl-dns-tests::cache
                      (list
                       (make-instance 'cl-dns:dns-rr :name "old.com" :type :a
                                      :ttl 300 :rdata "1.1.1.1")))
  (cl-dns:cache-store cl-dns-tests::cache
                      (list
                       (make-instance 'cl-dns:dns-rr :name "mid.com" :type :a
                                      :ttl 300 :rdata "2.2.2.2")))
  (cl-dns:cache-store cl-dns-tests::cache
                      (list
                       (make-instance 'cl-dns:dns-rr :name "new.com" :type :a
                                      :ttl 300 :rdata "3.3.3.3")))
  (cl-dns:cache-lookup cl-dns-tests::cache "old.com" :a)
  (cl-dns:cache-store cl-dns-tests::cache
                      (list
                       (make-instance 'cl-dns:dns-rr :name "newest.com" :type
                                      :a :ttl 300 :rdata "4.4.4.4")))
  (is (null (cl-dns:cache-lookup cl-dns-tests::cache "mid.com" :a)))
  (is (not (null (cl-dns:cache-lookup cl-dns-tests::cache "old.com" :a)))))
)

(test cache-save-and-load
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache))
      (cl-dns-tests::rr
       (make-instance 'cl-dns:dns-rr :name "persist.com" :type :a :ttl 600
                      :rdata "7.7.7.7"))
      (cl-dns-tests::path
       (merge-pathnames "cl-dns-test-cache.sexp"
                        (uiop/stream:temporary-directory))))
  (cl-dns:cache-store cl-dns-tests::cache (list cl-dns-tests::rr))
  (cl-dns:cache-save cl-dns-tests::cache cl-dns-tests::path)
  (let ((cl-dns-tests::cache2 (make-instance 'cl-dns:dns-cache)))
    (cl-dns:cache-load cl-dns-tests::cache2 cl-dns-tests::path)
    (let ((cl-dns-tests::result
           (cl-dns:cache-lookup cl-dns-tests::cache2 "persist.com" :a)))
      (is (not (null cl-dns-tests::result)))
      (is
       (string= "7.7.7.7" (cl-dns::rr-rdata (first cl-dns-tests::result))))))
  (delete-file cl-dns-tests::path))
)

(test cache-save-load-empty
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache))
      (cl-dns-tests::path
       (merge-pathnames "cl-dns-empty-test.sexp"
                        (uiop/stream:temporary-directory))))
  (cl-dns:cache-save cl-dns-tests::cache cl-dns-tests::path)
  (let ((cl-dns-tests::cache2 (make-instance 'cl-dns:dns-cache)))
    (cl-dns:cache-load cl-dns-tests::cache2 cl-dns-tests::path)
    (is (= 0 (hash-table-count (cl-dns::cache-entries cl-dns-tests::cache2)))))
  (delete-file cl-dns-tests::path))
)

(test cache-load-missing-file
  (let ((cl-dns-tests::cache (make-instance 'cl-dns:dns-cache))
      (cl-dns-tests::nonexistent
       (merge-pathnames "does-not-exist-xyz.sexp"
                        (uiop/stream:temporary-directory))))
  (cl-dns:cache-load cl-dns-tests::cache cl-dns-tests::nonexistent)
  (is (= 0 (hash-table-count (cl-dns::cache-entries cl-dns-tests::cache)))))
)

(def-suite :resolver :in :cl-dns)

(in-suite :resolver)

(test resolver-defaults
  (let ((cl-dns-tests::r
       (make-instance 'cl-dns:resolver :nameservers '("8.8.8.8"))))
  (is (equal '("8.8.8.8") (cl-dns::resolver-nameservers cl-dns-tests::r)))
  (is (= 5 (cl-dns::resolver-timeout cl-dns-tests::r)))
  (is (= 2 (cl-dns::resolver-retries cl-dns-tests::r))))
)

(test resolve-from-cache
  (let* ((cl-dns-tests::r (make-instance 'cl-dns:resolver))
       (cl-dns-tests::rr
        (make-instance 'cl-dns:dns-rr :name "cached.test" :type :a :ttl 300
                       :rdata "9.9.9.9")))
  (cl-dns:cache-store (cl-dns::resolver-cache cl-dns-tests::r)
                      (list cl-dns-tests::rr))
  (let ((cl-dns-tests::resp (cl-dns:resolve cl-dns-tests::r "cached.test" :a)))
    (is (not (null cl-dns-tests::resp)))
    (is (= 1 (cl-dns::header-qr (cl-dns::message-header cl-dns-tests::resp))))
    (is
     (string= "9.9.9.9"
              (cl-dns::rr-rdata
               (first (cl-dns::message-answers cl-dns-tests::resp)))))))
)

(test resolve-query-building
  (let ((cl-dns-tests::r
       (make-instance 'cl-dns:resolver :nameservers '("1.1.1.1" "8.8.8.8"))))
  ;; resolver holds the nameservers used when a query is dispatched
  (is (= 2 (length (cl-dns::resolver-nameservers cl-dns-tests::r))))
  (let ((cl-dns-tests::msg (cl-dns:make-query "test.com" :a :class :in)))
    (is
     (= 1 (cl-dns::header-qdcount (cl-dns::message-header cl-dns-tests::msg))))
    (let ((cl-dns-tests::bytes (cl-dns:encode-message cl-dns-tests::msg)))
      (is (> (length cl-dns-tests::bytes) 16))))))

(test resolve-cache-type-match
  (let* ((cl-dns-tests::r (make-instance 'cl-dns:resolver))
       (cl-dns-tests::rr
        (make-instance 'cl-dns:dns-rr :name "typed.test" :type :aaaa :ttl 300
                       :rdata "::1")))
  (cl-dns:cache-store (cl-dns::resolver-cache cl-dns-tests::r)
                      (list cl-dns-tests::rr))
  (let ((cl-dns-tests::resp
         (cl-dns:resolve cl-dns-tests::r "typed.test" :aaaa)))
    (is (= 1 (cl-dns::header-qr (cl-dns::message-header cl-dns-tests::resp))))
    (is
     (string= "::1"
              (cl-dns::rr-rdata
               (first (cl-dns::message-answers cl-dns-tests::resp)))))))
)

(test happy-eyeballs-from-cache
  (let* ((cl-dns-tests::r (make-instance 'cl-dns:resolver))
       (cl-dns-tests::rr4
        (make-instance 'cl-dns:dns-rr :name "dual.test" :type :a :ttl 300
                       :rdata "1.2.3.4"))
       (cl-dns-tests::rr6
        (make-instance 'cl-dns:dns-rr :name "dual.test" :type :aaaa :ttl 300
                       :rdata "::1")))
  (cl-dns:cache-store (cl-dns::resolver-cache cl-dns-tests::r)
                      (list cl-dns-tests::rr4 cl-dns-tests::rr6))
  (let ((cl-dns-tests::addrs
         (cl-dns:happy-eyeballs cl-dns-tests::r "dual.test" :timeout 1 :delay
                                0.05)))
    (is (string= "::1" (first cl-dns-tests::addrs)))
    (is (string= "1.2.3.4" (second cl-dns-tests::addrs)))))
)

(test happy-eyeballs-v4-only
  (let* ((cl-dns-tests::r (make-instance 'cl-dns:resolver))
       (cl-dns-tests::rr
        (make-instance 'cl-dns:dns-rr :name "v4only.test" :type :a :ttl 300
                       :rdata "5.5.5.5")))
  (cl-dns:cache-store (cl-dns::resolver-cache cl-dns-tests::r)
                      (list cl-dns-tests::rr))
  (let ((cl-dns-tests::addrs
         (cl-dns:happy-eyeballs cl-dns-tests::r "v4only.test" :timeout 1 :delay
                                0.05)))
    (is (= 1 (length cl-dns-tests::addrs)))
    (is (string= "5.5.5.5" (first cl-dns-tests::addrs)))))
)

(test resolve-negative-cache-hit
  (let* ((cl-dns-tests::r (make-instance 'cl-dns:resolver))
       (cl-dns-tests::rr
        (make-instance 'cl-dns:dns-rr :name "neg.test" :type :a :ttl 300 :rdata
                       :nxdomain)))
  (cl-dns:cache-store (cl-dns::resolver-cache cl-dns-tests::r)
                      (list cl-dns-tests::rr))
  (let ((cl-dns-tests::resp (cl-dns:resolve cl-dns-tests::r "neg.test" :a)))
    (is
     (= 3 (cl-dns::header-rcode (cl-dns::message-header cl-dns-tests::resp))))))
)

(test make-update-add-aaaa
  (let ((cl-dns-tests::msg
       (cl-dns::make-update-message "test.org"
                                    '((:op :add :name "a.test.org" :type :aaaa
                                       :ttl 120 :rdata "::1")))))
  (let ((cl-dns-tests::rr
         (first (cl-dns::message-authority cl-dns-tests::msg))))
    (is (eq :in (cl-dns::rr-class cl-dns-tests::rr)))
    (is (= 120 (cl-dns::rr-ttl cl-dns-tests::rr)))
    (is (string= "::1" (cl-dns::rr-rdata cl-dns-tests::rr)))))
)

(test dedup-single-query
  (let ((cl-dns-tests::dedup (make-instance 'cl-dns:query-deduplicator))
      (cl-dns-tests::call-count 0))
  (let ((cl-dns-tests::result
         (cl-dns:deduplicate-query cl-dns-tests::dedup "test.com" :a
                                   (lambda ()
                                     (incf cl-dns-tests::call-count)
                                     :answer))))
    (is (eq :answer cl-dns-tests::result))
    (is (= 1 cl-dns-tests::call-count))))
)

(test tsig-sign-basic
  (let* ((cl-dns-tests::msg (cl-dns:make-query "test.com" :a))
       (cl-dns-tests::key
        (make-array 32 :element-type '(unsigned-byte 8) :initial-element 66))
       (cl-dns-tests::signed
        (cl-dns:tsig-sign cl-dns-tests::msg "mykey" cl-dns-tests::key)))
  (is (stringp (getf cl-dns-tests::signed :key-name)))
  (is (> (length (getf cl-dns-tests::signed :mac)) 0))
  (is (= 300 (getf cl-dns-tests::signed :fudge))))
)

(test tsig-sign-deterministic
  (let* ((cl-dns-tests::msg (cl-dns:make-query "sign.com" :a))
       (cl-dns-tests::key
        (make-array 32 :element-type '(unsigned-byte 8) :initial-element 17))
       (cl-dns-tests::s1
        (cl-dns:tsig-sign cl-dns-tests::msg "k" cl-dns-tests::key :algorithm
                          :hmac-sha256))
       (cl-dns-tests::s2
        (cl-dns:tsig-sign cl-dns-tests::msg "k" cl-dns-tests::key :algorithm
                          :hmac-sha256)))
  (is (equalp (getf cl-dns-tests::s1 :mac) (getf cl-dns-tests::s2 :mac))))
)

(test tsig-sign-different-keys
  (let* ((cl-dns-tests::msg (cl-dns:make-query "x.com" :a))
       (cl-dns-tests::key1
        (make-array 16 :element-type '(unsigned-byte 8) :initial-element 170))
       (cl-dns-tests::key2
        (make-array 16 :element-type '(unsigned-byte 8) :initial-element 187))
       (cl-dns-tests::s1
        (cl-dns:tsig-sign cl-dns-tests::msg "k" cl-dns-tests::key1))
       (cl-dns-tests::s2
        (cl-dns:tsig-sign cl-dns-tests::msg "k" cl-dns-tests::key2)))
  (is (not (equalp (getf cl-dns-tests::s1 :mac) (getf cl-dns-tests::s2 :mac)))))
)

(test dedup-different-queries
  (let ((cl-dns-tests::dedup (make-instance 'cl-dns:query-deduplicator)))
  (let ((cl-dns-tests::r1
         (cl-dns:deduplicate-query cl-dns-tests::dedup "a.com" :a
                                   (lambda () :first)))
        (cl-dns-tests::r2
         (cl-dns:deduplicate-query cl-dns-tests::dedup "b.com" :a
                                   (lambda () :second))))
    (is (eq :first cl-dns-tests::r1))
    (is (eq :second cl-dns-tests::r2))))
)

(test resolve-parallel-from-cache
  (let* ((cl-dns-tests::r (make-instance 'cl-dns:resolver))
       (cl-dns-tests::rr4
        (make-instance 'cl-dns:dns-rr :name "par.test" :type :a :ttl 300 :rdata
                       "2.2.2.2"))
       (cl-dns-tests::rr6
        (make-instance 'cl-dns:dns-rr :name "par.test" :type :aaaa :ttl 300
                       :rdata "::2")))
  (cl-dns:cache-store (cl-dns::resolver-cache cl-dns-tests::r)
                      (list cl-dns-tests::rr4 cl-dns-tests::rr6))
  (let ((cl-dns-tests::results
         (cl-dns:resolve-parallel cl-dns-tests::r
                                  '(("par.test" :a) ("par.test" :aaaa))
                                  :timeout 1)))
    (is (= 2 (length cl-dns-tests::results)))
    (is (not (null (first cl-dns-tests::results))))
    (is (not (null (second cl-dns-tests::results))))))
)

(def-suite :dnssec :in :cl-dns)

(in-suite :dnssec)

(test decode-dnskey-basic
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref cl-dns-tests::buf 0) 1
        (aref cl-dns-tests::buf 1) 1
        (aref cl-dns-tests::buf 2) 3
        (aref cl-dns-tests::buf 3) 8
        (aref cl-dns-tests::buf 4) 171
        (aref cl-dns-tests::buf 5) 205
        (aref cl-dns-tests::buf 6) 239
        (aref cl-dns-tests::buf 7) 1)
  (let ((cl-dns-tests::result (cl-dns::decode-dnskey cl-dns-tests::buf 0 8)))
    (is (= 257 (getf cl-dns-tests::result :flags)))
    (is (= 3 (getf cl-dns-tests::result :protocol)))
    (is (= 8 (getf cl-dns-tests::result :algorithm)))
    (is (= 4 (length (getf cl-dns-tests::result :public-key))))))
)

(test decode-ds-basic
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref cl-dns-tests::buf 0) (ash 12345 -8)
        (aref cl-dns-tests::buf 1) (logand 12345 255)
        (aref cl-dns-tests::buf 2) 8
        (aref cl-dns-tests::buf 3) 2
        (aref cl-dns-tests::buf 4) 170
        (aref cl-dns-tests::buf 5) 187
        (aref cl-dns-tests::buf 6) 204
        (aref cl-dns-tests::buf 7) 221)
  (let ((cl-dns-tests::result (cl-dns::decode-ds cl-dns-tests::buf 0 8)))
    (is (= 12345 (getf cl-dns-tests::result :key-tag)))
    (is (= 8 (getf cl-dns-tests::result :algorithm)))
    (is (= 2 (getf cl-dns-tests::result :digest-type)))
    (is (= 4 (length (getf cl-dns-tests::result :digest))))))
)

(test compute-key-tag-basic
  (let ((cl-dns-tests::dnskey
       (list :flags 257 :protocol 3 :algorithm 8 :public-key
             (make-array 4 :element-type '(unsigned-byte 8) :initial-contents
                         '(171 205 239 1)))))
  (let ((cl-dns-tests::tag (cl-dns::compute-key-tag cl-dns-tests::dnskey)))
    (is (integerp cl-dns-tests::tag))
    (is (<= 0 cl-dns-tests::tag 65535))))
)

(test trust-anchor-add
  (let ((cl-dns-tests::store (make-instance 'cl-dns:trust-anchor-store))
      (cl-dns-tests::key
       '(:flags 257 :protocol 3 :algorithm 8 :public-key #(1 2 3))))
  (cl-dns:add-trust-anchor cl-dns-tests::store "example.com" cl-dns-tests::key)
  (is
   (= 1
      (length
       (gethash "example.com" (cl-dns::trust-anchors cl-dns-tests::store))))))
)

(test validate-dnssec-insecure
  (let* ((cl-dns-tests::resp (make-instance 'cl-dns:dns-message))
       (cl-dns-tests::result
        (cl-dns:validate-dnssec (make-instance 'cl-dns:resolver)
                                cl-dns-tests::resp)))
  (is (eq :insecure cl-dns-tests::result)))
)

(test build-signing-input-basic
  (let* ((cl-dns-tests::rrsig
        (list :type-covered 1 :algorithm 8 :labels 2 :original-ttl 3600
              :expiration 1000000 :inception 900000 :key-tag 12345 :signer
              "example.com"))
       (cl-dns-tests::rrset
        (list
         (make-instance 'cl-dns:dns-rr :name "test.example.com" :type :a :class
                        :in :ttl 3600 :rdata #(1 2 3 4))))
       (cl-dns-tests::input
        (cl-dns::build-signing-input cl-dns-tests::rrset cl-dns-tests::rrsig)))
  (is (> (length cl-dns-tests::input) 0))
  (is (= 0 (aref cl-dns-tests::input 0)))
  (is (= 1 (aref cl-dns-tests::input 1))))
)

(test build-signing-input-canonical-order
  (let* ((cl-dns-tests::rrsig
        (list :type-covered 1 :algorithm 8 :labels 2 :original-ttl 300
              :expiration 99999 :inception 88888 :key-tag 55555 :signer
              "example.com"))
       (cl-dns-tests::rr1
        (make-instance 'cl-dns:dns-rr :name "b.example.com" :type :a :class :in
                       :ttl 300 :rdata #(2 2 2 2)))
       (cl-dns-tests::rr2
        (make-instance 'cl-dns:dns-rr :name "a.example.com" :type :a :class :in
                       :ttl 300 :rdata #(1 1 1 1)))
       (cl-dns-tests::input
        (cl-dns::build-signing-input (list cl-dns-tests::rr1 cl-dns-tests::rr2)
                                     cl-dns-tests::rrsig)))
  (is (> (length cl-dns-tests::input) 50)))
)

(test verify-ds-sha256
  (let* ((cl-dns-tests::dnskey
        (list :flags 257 :protocol 3 :algorithm 8 :public-key
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element
                          171)))
       (cl-dns-tests::buf
        (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0))
       (cl-dns-tests::offset
        (cl-dns:encode-name "example.com" cl-dns-tests::buf 0)))
  (setf (aref cl-dns-tests::buf cl-dns-tests::offset) 1
        (aref cl-dns-tests::buf (+ cl-dns-tests::offset 1)) 1)
  (incf cl-dns-tests::offset 2)
  (setf (aref cl-dns-tests::buf cl-dns-tests::offset) 3)
  (incf cl-dns-tests::offset)
  (setf (aref cl-dns-tests::buf cl-dns-tests::offset) 8)
  (incf cl-dns-tests::offset)
  (replace cl-dns-tests::buf (getf cl-dns-tests::dnskey :public-key) :start1
           cl-dns-tests::offset)
  (incf cl-dns-tests::offset 32)
  (let* ((cl-dns-tests::expected-digest
          (ironclad:digest-sequence :sha256
                                    (subseq cl-dns-tests::buf 0
                                            cl-dns-tests::offset)))
         (cl-dns-tests::ds
          (list :key-tag 0 :algorithm 8 :digest-type 2 :digest
                cl-dns-tests::expected-digest)))
    (is
     (cl-dns::verify-ds cl-dns-tests::ds cl-dns-tests::dnskey "example.com"))))
)

(test verify-ds-mismatch
  (let ((cl-dns-tests::ds
       (list :key-tag 0 :algorithm 8 :digest-type 2 :digest
             (make-array 32 :element-type '(unsigned-byte 8) :initial-element
                         0)))
      (cl-dns-tests::dnskey
       (list :flags 257 :protocol 3 :algorithm 8 :public-key
             (make-array 4 :element-type '(unsigned-byte 8) :initial-contents
                         '(1 2 3 4)))))
  (is
   (not
    (cl-dns::verify-ds cl-dns-tests::ds cl-dns-tests::dnskey "example.com"))))
)

(test verify-ds-unknown-digest-type
  (let ((cl-dns-tests::ds
       (list :key-tag 0 :algorithm 8 :digest-type 99 :digest #(1 2 3)))
      (cl-dns-tests::dnskey
       (list :flags 257 :protocol 3 :algorithm 8 :public-key #(1 2 3 4))))
  (is
   (null (cl-dns::verify-ds cl-dns-tests::ds cl-dns-tests::dnskey "test.com"))))
)

(test verify-rrsig-unknown-algo
  (let ((cl-dns-tests::rrsig
       (list :type-covered 1 :algorithm 99 :labels 2 :original-ttl 300
             :expiration 99999 :inception 88888 :key-tag 100 :signer "x.com"
             :signature #(1 2 3)))
      (cl-dns-tests::dnskey
       (list :flags 257 :protocol 3 :algorithm 99 :public-key #(4 5 6))))
  (is
   (null (cl-dns:verify-rrsig cl-dns-tests::rrsig cl-dns-tests::dnskey nil))))
)

(test decode-nsec-basic
  (let ((cl-dns-tests::buf
       (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
  (let ((cl-dns-tests::off (cl-dns:encode-name "b.com" cl-dns-tests::buf 0)))
    (setf (aref cl-dns-tests::buf cl-dns-tests::off) 0
          (aref cl-dns-tests::buf (+ cl-dns-tests::off 1)) 1
          (aref cl-dns-tests::buf (+ cl-dns-tests::off 2)) 64)
    (let ((cl-dns-tests::result
           (cl-dns::decode-nsec cl-dns-tests::buf 0 (+ cl-dns-tests::off 3))))
      (is (string= "b.com" (getf cl-dns-tests::result :next-domain)))
      (is (member 1 (getf cl-dns-tests::result :types))))))
)

(test decode-nsec3-basic
  (let ((cl-dns-tests::buf
       (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
  (setf (aref cl-dns-tests::buf 0) 1
        (aref cl-dns-tests::buf 1) 0
        (aref cl-dns-tests::buf 2) 0
        (aref cl-dns-tests::buf 3) 10
        (aref cl-dns-tests::buf 4) 4
        (aref cl-dns-tests::buf 5) 170
        (aref cl-dns-tests::buf 6) 187
        (aref cl-dns-tests::buf 7) 204
        (aref cl-dns-tests::buf 8) 221)
  (setf (aref cl-dns-tests::buf 9) 4
        (aref cl-dns-tests::buf 10) 1
        (aref cl-dns-tests::buf 11) 2
        (aref cl-dns-tests::buf 12) 3
        (aref cl-dns-tests::buf 13) 4)
  (setf (aref cl-dns-tests::buf 14) 0
        (aref cl-dns-tests::buf 15) 1
        (aref cl-dns-tests::buf 16) 64)
  (let ((cl-dns-tests::result (cl-dns::decode-nsec3 cl-dns-tests::buf 0 17)))
    (is (= 1 (getf cl-dns-tests::result :algorithm)))
    (is (= 10 (getf cl-dns-tests::result :iterations)))
    (is (= 4 (length (getf cl-dns-tests::result :salt))))
    (is (member 1 (getf cl-dns-tests::result :types)))))
)

(test verify-denial-nsec
  (let* ((cl-dns-tests::nsec-rr
        (make-instance 'cl-dns:dns-rr :name "a.example.com" :type :nsec :class
                       :in :ttl 300 :rdata
                       (list :next-domain "c.example.com" :types '(1 28)))))
  (is (cl-dns:verify-denial "b.example.com" :mx (list cl-dns-tests::nsec-rr)))
  (is
   (not
    (cl-dns:verify-denial "b.example.com" :a (list cl-dns-tests::nsec-rr)))))
)

(test verify-denial-nsec3
  (let* ((cl-dns-tests::nsec3-rr
        (make-instance 'cl-dns:dns-rr :name "abc.example.com" :type :nsec3
                       :class :in :ttl 300 :rdata
                       (list :algorithm 1 :flags 0 :iterations 10 :salt #(1 2)
                             :next-hashed #(3 4) :types '(1 28 46)))))
  (is
   (cl-dns:verify-denial "test.example.com" :mx (list cl-dns-tests::nsec3-rr)))
  (is
   (not
    (cl-dns:verify-denial "test.example.com" :a
                          (list cl-dns-tests::nsec3-rr)))))
)

(test verify-denial-empty-records
  (is (not (cl-dns:verify-denial "x.com" :a nil)))
)

(test verify-rrsig-bad-signature
  (let ((cl-dns-tests::rrsig-data
       (list :type-covered 1 :algorithm 8 :labels 2 :original-ttl 300
             :expiration 1 :inception 0 :key-tag 999 :signer "ex.com"
             :signature
             (make-array 64 :element-type '(unsigned-byte 8) :initial-element
                         0)))
      (cl-dns-tests::dnskey
       (list :flags 257 :protocol 3 :algorithm 8 :public-key
             (make-array 128 :element-type '(unsigned-byte 8) :initial-element
                         1)))
      (cl-dns-tests::rrset
       (list
        (make-instance 'cl-dns:dns-rr :name "x.ex.com" :type :a :class :in :ttl
                       300 :rdata #(1 2 3 4)))))
  (is
   (null
    (cl-dns:verify-rrsig cl-dns-tests::rrsig-data cl-dns-tests::dnskey
                         cl-dns-tests::rrset))))
)

;;; Coverage: 37/52 functions tested
