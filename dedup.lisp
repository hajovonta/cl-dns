(in-package #:cl-dns)

(defclass query-deduplicator ()
  ((in-flight :initform (make-hash-table :test 'equal) :accessor dedup-in-flight)
   (lock :initform (bt:make-lock "dedup") :accessor dedup-lock))
  (:documentation "Query deduplication table tracking in-flight queries."))
(defun deduplicate-query (deduper name type thunk)
  "Collapse identical in-flight queries into one, returning the same result to all waiters."
  (let ((key (cons (string-downcase name) type)))
    (bt:with-lock-held ((dedup-lock deduper))
      (let ((existing (gethash key (dedup-in-flight deduper))))
        (when existing
          ;; Wait for existing query to complete
          (bt:with-lock-held ((car existing))
            (return-from deduplicate-query (cdr existing))))))
    ;; No in-flight query — register ourselves
    (let ((result-lock (bt:make-lock "dedup-result")))
      (bt:acquire-lock result-lock)
      (bt:with-lock-held ((dedup-lock deduper))
        (setf (gethash key (dedup-in-flight deduper)) (cons result-lock nil)))
      ;; Execute the query
      (let ((result (funcall thunk)))
        ;; Store result and release waiters
        (bt:with-lock-held ((dedup-lock deduper))
          (let ((entry (gethash key (dedup-in-flight deduper))))
            (when entry (setf (cdr entry) result)))
          (remhash key (dedup-in-flight deduper)))
        (bt:release-lock result-lock)
        result))))
