(ns telehash.byte-utils
  (:import [org.apache.commons.codec.binary Hex]
           [java.nio ByteBuffer]))

(def byte-array-class (Class/forName "[B"))

(defn ensure-byte-array [seq-or-bytes]
  (if (instance? byte-array-class seq-or-bytes)
    seq-or-bytes
    (byte-array seq-or-bytes)))

(defn bytes->hex [seq-or-bytes]
  (Hex/encodeHexString (ensure-byte-array seq-or-bytes)))

(defn hex->bytes [hex]
  (Hex/decodeHex (char-array hex)))

(defn int->bytes [x]
  (let [buffer (ByteBuffer/allocate 4)]
    (.putInt buffer x)
    (.array buffer)))

(defn fold
  ([bytes] (fold bytes 1))
  ([bytes n]
   (if (or (>= 0 n) ((complement even?) (count bytes))) bytes
       (let [[p1 p2] (split-at (/ (count bytes) 2) bytes)
             folded (byte-array (map bit-xor p1 p2))]
         (recur folded (- n 1))))))

(defn take-n [bytes-or-seq n]
  (take n bytes-or-seq))

(defn- zeros* [n]
  (byte-array (repeat n 0x00)))

(def zeros (memoize zeros*))


(defn make-n-bytes [bytes n]
  (let [actual-n (count bytes)]
    (if (< actual-n n)
      (byte-array (concat (zeros (- n actual-n)) bytes))
      (byte-array (take-last n bytes))
      )))

(defn right-zero-padded [bytes total-n]
  (let [actual-n (count bytes)]
    (if (> actual-n total-n)
      (take total-n bytes)
      (concat bytes (zeros (- total-n actual-n))))))
