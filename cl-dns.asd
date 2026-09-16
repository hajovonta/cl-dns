(asdf:defsystem "cl-dns"
  :author "Hajovonta"
  :license "MIT"
  :description "Async DNS resolver with DoH, DoT, DNSSEC, mDNS/DNS-SD, TSIG, and dynamic updates."
  :depends-on (#:bordeaux-threads
               #:cl+ssl
               #:cl-crypto-util
               #:dexador
               #:flexi-streams
               #:ironclad
               #:split-sequence
               #:usocket)
  :components ((:file "package")
               (:file "protocol")
               (:file "dynamic")
               (:file "dnssec")
               (:file "iterative")
               (:file "pool")
               (:file "cache")
               (:file "resolver")
               (:file "nsec")
               (:file "mdns")
               (:file "transport")
               (:file "dot")
               (:file "dedup")
               (:file "conditions")
               (:file "doh")
               (:file "tsig")
))
