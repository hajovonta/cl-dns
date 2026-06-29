(in-package #:cl-dns)

(defun cache-purge (cache)
  "Remove expired entries from the cache."
  (let ((now (get-universal-time)))
    (maphash (lambda (key entry)
               (when (> now (car entry))
                 (remhash key (cache-entries cache))))
             (cache-entries cache))))
(defun cache-lookup (cache name type)
  "Look up cached records for a name/type pair. Returns NIL if expired or missing."
  (let* ((key (cons (string-downcase name) type))
         (now (get-universal-time))
         (entry (gethash key (cache-entries cache))))
    (when entry
      (let ((expiry (car entry))
            (records (cdr entry)))
        (if (> now expiry)
            (progn (remhash key (cache-entries cache)) nil)
            (progn
              ;; Move to front of access order
              (setf (cache-access-order cache)
                    (cons key (remove key (cache-access-order cache) :test #'equal)))
              records))))))
(defun cache-store (cache records)
  "Store RRs in the cache, respecting their TTL for expiry."
  (let ((now (get-universal-time)))
    (dolist (rr records)
      (let* ((key (cons (string-downcase (rr-name rr)) (rr-type rr)))
             (expiry (+ now (rr-ttl rr)))
             (existing (gethash key (cache-entries cache))))
        (if existing
            (setf (car existing) (max (car existing) expiry)
                  (cdr existing) (append (cdr existing) (list rr)))
            (setf (gethash key (cache-entries cache)) (cons expiry (list rr))))
        (setf (cache-access-order cache)
              (cons key (remove key (cache-access-order cache) :test #'equal))))))
  (cache-evict-lru cache))
(defclass dns-cache ()
  ((entries :initform (make-hash-table :test 'equal) :accessor cache-entries)
   (max-size :initarg :max-size :initform 1000 :accessor cache-max-size)
   (access-order :initform nil :accessor cache-access-order))
  (:documentation "DNS cache mapping (name, type, class) to cached RRs with expiry times."))

(defun cache-evict-lru (cache)
  "Evict least-recently-used entries when cache exceeds max-size."
  (loop while (> (hash-table-count (cache-entries cache)) (cache-max-size cache))
        for order = (cache-access-order cache)
        for victim = (car (last order))
        do (remhash victim (cache-entries cache))
           (setf (cache-access-order cache) (butlast order))))

(defun cache-store-negative (cache name type authority-section)
  "Cache a negative response (NXDOMAIN) using the SOA minimum TTL."
  (let ((soa (find :soa authority-section :key #'rr-type)))
    (when soa
      (let* ((soa-data (rr-rdata soa))
             ;; SOA minimum TTL is the last field in RDATA (for parsed SOA)
             (neg-ttl (if (listp soa-data)
                          (or (getf soa-data :minimum) 300)
                          300))
             (neg-rr (make-instance 'dns-rr
                       :name name :type type :class :in
                       :ttl neg-ttl :rdata :nxdomain)))
        (cache-store cache (list neg-rr))))))

(defun cache-load (cache pathname)
  "Load cache contents from a file, discarding expired entries."
  (when (probe-file pathname)
    (with-open-file (in pathname :direction :input)
      (loop for entry = (read in nil :eof)
            until (eq entry :eof)
            when (and (listp entry) (> (getf entry :ttl 0) 0))
            do (cache-store cache
                 (list (make-instance 'dns-rr
                         :name (getf entry :name)
                         :type (getf entry :type)
                         :class (getf entry :class :in)
                         :ttl (getf entry :ttl)
                         :rdata (getf entry :rdata))))))))

(defun cache-save (cache pathname)
  "Save the cache contents to a file for persistence across restarts."
  (with-open-file (out pathname :direction :output :if-exists :supersede)
    (let ((now (get-universal-time)))
      (maphash (lambda (key entry)
                 (let ((expiry (car entry))
                       (records (cdr entry)))
                   (when (> expiry now)
                     (dolist (rr records)
                       (print (list :name (rr-name rr) :type (rr-type rr)
                                    :class (rr-class rr) :ttl (- expiry now)
                                    :rdata (rr-rdata rr))
                              out)))))
               (cache-entries cache))))
  pathname)
