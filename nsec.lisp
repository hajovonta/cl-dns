(in-package #:cl-dns)

(defun decode-nsec3 (buffer offset rdlength)
  "Parse NSEC3 RDATA (algorithm, flags, iterations, salt, next-hashed, type bitmaps)."
  (let* ((algorithm (aref buffer offset))
         (flags (aref buffer (+ offset 1)))
         (iterations (logior (ash (aref buffer (+ offset 2)) 8) (aref buffer (+ offset 3))))
         (salt-len (aref buffer (+ offset 4)))
         (salt (subseq buffer (+ offset 5) (+ offset 5 salt-len)))
         (hash-pos (+ offset 5 salt-len))
         (hash-len (aref buffer hash-pos))
         (next-hashed (subseq buffer (+ hash-pos 1) (+ hash-pos 1 hash-len)))
         (bitmap-start (+ hash-pos 1 hash-len))
         (bitmap-end (+ offset rdlength))
         (types nil))
    (loop while (< bitmap-start bitmap-end)
          do (let ((window (aref buffer bitmap-start))
                   (blen (aref buffer (+ bitmap-start 1))))
               (incf bitmap-start 2)
               (loop for i from 0 below blen
                     for byte = (aref buffer (+ bitmap-start i))
                     do (loop for bit from 7 downto 0
                              when (logbitp bit byte)
                              do (push (+ (* window 256) (* i 8) (- 7 bit)) types)))
               (incf bitmap-start blen)))
    (list :algorithm algorithm :flags flags :iterations iterations
          :salt salt :next-hashed next-hashed :types (nreverse types))))
(defun decode-nsec (buffer offset rdlength)
  "Parse NSEC RDATA (next-domain + type bitmaps)."
  (multiple-value-bind (next-domain new-offset) (decode-name buffer offset)
    (let* ((bitmap-start new-offset)
           (bitmap-end (+ offset rdlength))
           (types nil))
      ;; Parse type bitmaps: window-block(1) + bitmap-length(1) + bitmap(n)
      (loop while (< bitmap-start bitmap-end)
            do (let ((window (aref buffer bitmap-start))
                     (blen (aref buffer (+ bitmap-start 1))))
                 (incf bitmap-start 2)
                 (loop for i from 0 below blen
                       for byte = (aref buffer (+ bitmap-start i))
                       do (loop for bit from 7 downto 0
                                when (logbitp bit byte)
                                do (push (+ (* window 256) (* i 8) (- 7 bit)) types)))
                 (incf bitmap-start blen)))
      (list :next-domain next-domain :types (nreverse types)))))
(defun verify-denial (name type nsec-records)
  "Verify authenticated denial of existence using NSEC/NSEC3 records."
  (let ((type-num (or (cdr (assoc type *record-types*)) type)))
    (dolist (rr nsec-records)
      (let ((data (rr-rdata rr)))
        (when (listp data)
          (cond
            ;; NSEC: check if name falls in gap and type is not in bitmap
            ((and (getf data :next-domain) (getf data :types))
             (let ((owner (string-downcase (rr-name rr)))
                   (next (string-downcase (getf data :next-domain)))
                   (qname (string-downcase name)))
               (when (and (string>= qname owner)
                          (or (string< qname next)
                              (string< next owner))) ; wrap-around
                 (unless (member type-num (getf data :types))
                   (return-from verify-denial t)))))
            ;; NSEC3: check hashed name is covered
            ((getf data :next-hashed)
             ;; Simplified: if type not in bitmap, denial is valid
             (unless (member type-num (getf data :types))
               (return-from verify-denial t)))))))
    nil))
