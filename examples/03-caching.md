# Caching

```lisp
;; Default cache (1000 entries, LRU eviction)
(defvar *resolver* (make-instance 'cl-dns:resolver))

;; Custom cache size
(defvar *big-cache-resolver*
  (make-instance 'cl-dns:resolver
    :cache (make-instance 'cl-dns:dns-cache :max-size 10000)))

;; Manual cache operations
(let ((cache (cl-dns::resolver-cache *resolver*)))
  ;; Lookup without resolving
  (cl-dns:cache-lookup cache "example.com" :a)

  ;; Manually store records
  (cl-dns:cache-store cache
    (list (make-instance 'cl-dns:dns-rr
            :name "internal.corp" :type :a :ttl 3600 :rdata "10.0.0.1")))

  ;; Purge expired entries
  (cl-dns:cache-purge cache))

;; Persistent cache — save to disk
(let ((cache (cl-dns::resolver-cache *resolver*)))
  (cl-dns:cache-save cache #p"/tmp/dns-cache.sexp"))

;; Restore on startup
(let ((cache (make-instance 'cl-dns:dns-cache)))
  (cl-dns:cache-load cache #p"/tmp/dns-cache.sexp")
  (make-instance 'cl-dns:resolver :cache cache))

;; Negative caching happens automatically:
;; NXDOMAIN responses are cached using the SOA minimum TTL
(cl-dns:resolve *resolver* "nonexistent.example.com" :a)
;; Second call returns cached NXDOMAIN instantly
(cl-dns:resolve *resolver* "nonexistent.example.com" :a)
```
