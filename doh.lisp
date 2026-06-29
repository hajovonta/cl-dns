(in-package #:cl-dns)

(defun doh-query (url query-bytes &key (timeout 5))
  "Send a DNS query via DNS-over-HTTPS (RFC 8484) using POST with application/dns-message.
Requires dexador to be loaded."
  (declare (ignore timeout))
  (let ((post-fn (or (find-symbol "POST" "DEXADOR")
                     (error "dexador not loaded — (ql:quickload :dexador)"))))
    (multiple-value-bind (body status)
        (funcall post-fn url
                 :content query-bytes
                 :headers '(("content-type" . "application/dns-message")
                            ("accept" . "application/dns-message")))
      (if (= status 200)
          (decode-message body)
          (error "DoH query failed with status ~D" status)))))
