(in-package #:cl-dns)

(defclass connection-pool ()
  ((connections :initform (make-hash-table :test 'equal) :accessor pool-connections)
   (max-idle :initarg :max-idle :initform 4 :accessor pool-max-idle)
   (lock :initform (bt:make-lock "conn-pool") :accessor pool-lock))
  (:documentation "Pool of reusable TLS connections to DoT servers, keyed by (host, port)."))
(defun pool-acquire (pool host port &key tls)
  "Acquire a connection from the pool (or create a new one if none available)."
  (let ((key (cons host port)))
    (bt:with-lock-held ((pool-lock pool))
      (let ((idle (gethash key (pool-connections pool))))
        (when idle
          (let ((conn (pop (gethash key (pool-connections pool)))))
            (when conn (return-from pool-acquire conn))))))
    ;; No idle connection — create new
    (let ((socket (usocket:socket-connect host port
                    :element-type '(unsigned-byte 8)
                    :timeout 10)))
      (if tls
          (cl+ssl:make-ssl-client-stream
           (usocket:socket-stream socket)
           :hostname host)
          (usocket:socket-stream socket)))))
(defun pool-release (pool host port conn)
  "Return a connection to the pool for reuse."
  (let ((key (cons host port)))
    (bt:with-lock-held ((pool-lock pool))
      (let ((idle (gethash key (pool-connections pool))))
        (if (>= (length idle) (pool-max-idle pool))
            (ignore-errors (close conn))
            (push conn (gethash key (pool-connections pool))))))))
(defun pool-close-all (pool)
  "Close all idle connections in the pool."
  (bt:with-lock-held ((pool-lock pool))
    (maphash (lambda (key conns)
               (declare (ignore key))
               (dolist (c conns)
                 (ignore-errors (close c))))
             (pool-connections pool))
    (clrhash (pool-connections pool))))
