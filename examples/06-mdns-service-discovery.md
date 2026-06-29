# mDNS & DNS-SD (Service Discovery)

```lisp
;; Query a .local hostname via multicast DNS
(cl-dns:mdns-query "myprinter.local" :a :timeout 2)

;; Discover HTTP services on the local network
(cl-dns:discover-services "_http._tcp")
;; => ("MyWebServer._http._tcp.local" "Printer._http._tcp.local" ...)

;; Discover all services of a type
(cl-dns:discover-services "_ipp._tcp")      ; printers
(cl-dns:discover-services "_ssh._tcp")      ; SSH servers
(cl-dns:discover-services "_mqtt._tcp")     ; MQTT brokers
(cl-dns:discover-services "_http._tcp")     ; web servers

;; Get details about a discovered service (SRV + TXT)
(let ((resp (cl-dns:mdns-query "MyPrinter._ipp._tcp.local" :srv :timeout 2)))
  (when resp
    (dolist (rr (cl-dns::message-answers resp))
      (format t "~A: ~A~%" (cl-dns::rr-type rr) (cl-dns::rr-rdata rr)))))
```
