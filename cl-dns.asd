;;;; cl-dns.asd

(asdf:defsystem #:cl-dns
  :description "Async DNS resolver with DNS-over-HTTPS and DNS-over-TLS support."
  :author "Hajovonta"
  :license "MIT"
  :version "0.1.0"
  :serial t
  :depends-on (#:bordeaux-threads #:bordeaux-threads #:cl+ssl #:cl+ssl #:dexador #:dexador #:flexi-streams #:flexi-streams #:ironclad #:ironclad #:split-sequence #:split-sequence #:usocket #:usocket)
  :components ((:file "package")
               (:file "protocol")
               (:file "cache")
               (:file "resolver")
               (:file "doh")
               (:file "dot")
               (:file "mdns")
               (:file "dnssec")
               (:file "iterative")
               (:file "dynamic")
               (:file "pool")
               (:file "conditions")
               (:file "transport")
               (:file "tsig")
               (:file "nsec")
               (:file "dedup")))
