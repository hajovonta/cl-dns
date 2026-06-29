# Query Deduplication

```lisp
;; Prevents duplicate network requests for identical in-flight queries

(defvar *dedup* (make-instance 'cl-dns:query-deduplicator))
(defvar *resolver* (make-instance 'cl-dns:resolver))

;; Wrap resolution calls with deduplication
(defun resolve-deduped (name type)
  (cl-dns:deduplicate-query *dedup* name type
    (lambda ()
      (cl-dns:resolve *resolver* name type))))

;; If multiple threads call (resolve-deduped "example.com" :a) simultaneously,
;; only ONE network query is sent. All callers get the same result.

;; Example: parallel requests that deduplicate
(let ((threads
        (loop repeat 10
              collect (bt:make-thread
                       (lambda () (resolve-deduped "google.com" :a))))))
  ;; Only 1 DNS query is actually sent to the network
  (mapcar #'bt:join-thread threads))
```
