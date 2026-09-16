(in-package #:cl-dns)

(defparameter *root-servers*
  '(("a.root-servers.net" . "198.41.0.4")
    ("b.root-servers.net" . "170.247.170.2")
    ("c.root-servers.net" . "192.33.4.12")
    ("d.root-servers.net" . "199.7.91.13")
    ("e.root-servers.net" . "192.203.230.10")
    ("f.root-servers.net" . "192.5.5.241")
    ("g.root-servers.net" . "192.112.36.4")
    ("h.root-servers.net" . "198.97.190.53")
    ("i.root-servers.net" . "192.36.148.17")
    ("j.root-servers.net" . "192.58.128.30")
    ("k.root-servers.net" . "193.0.14.129")
    ("l.root-servers.net" . "199.7.83.42")
    ("m.root-servers.net" . "202.12.27.33"))
  "Root server hints (name/IP pairs for bootstrapping iterative resolution).")
(declaim (special *root-servers*))
(defun resolve-iterative (name type &key (timeout 5))
  "Resolve a query iteratively from root servers, following delegations."
  (let ((query (make-query name type :recursion-desired nil))
        (servers (mapcar #'cdr *root-servers*)))
    (loop for depth from 0 below 20
          do (let* ((ns (nth (mod depth (length servers)) servers))
                    (bytes (encode-message query))
                    (resp-bytes (handler-case
                                   (send-query-udp ns bytes :timeout timeout)
                                 (error () nil))))
               (unless resp-bytes (return nil))
               (let* ((resp (decode-message resp-bytes))
                      (hdr (message-header resp))
                      (rcode (header-rcode hdr)))
                 ;; Got authoritative answer or error
                 (when (or (= 1 (header-aa hdr))
                           (message-answers resp)
                           (and (/= 0 rcode) (/= 0 (header-rcode hdr))))
                   (return resp))
                 ;; Follow delegation: extract NS from authority + glue from additional
                 (let ((ns-rrs (remove-if-not (lambda (rr) (eq :ns (rr-type rr)))
                                              (message-authority resp)))
                       (glue (message-additional resp)))
                   (unless ns-rrs (return resp))
                   ;; Find glue A records for delegated nameservers
                   (let ((new-servers
                           (loop for ns-rr in ns-rrs
                                 for ns-name = (rr-rdata ns-rr)
                                 for glue-rr = (find ns-name glue
                                                     :key #'rr-name :test #'string-equal)
                                 when (and glue-rr (eq :a (rr-type glue-rr)))
                                 collect (rr-rdata glue-rr))))
                     (if new-servers
                         (setf servers new-servers)
                         ;; No glue: resolve NS name recursively
                         (let ((ns-name (rr-rdata (first ns-rrs))))
                           (let ((ns-resp (resolve-iterative ns-name :a :timeout timeout)))
                             (when (and ns-resp (message-answers ns-resp))
                               (setf servers
                                     (mapcar #'rr-rdata
                                             (remove-if-not (lambda (rr) (eq :a (rr-type rr)))
                                                            (message-answers ns-resp))))))))))))
          finally (return nil))))
