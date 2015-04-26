(ns telehash.e3x
  (:refer-clojure :exclude [key])
  (:import [java.nio ByteBuffer]
           [org.apache.commons.codec.binary Hex]))

;; This should be somewhere in the core?
(java.security.Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defrecord E3X [cs session])

(defprotocol CipherSet
  (cipher-set-id [_])
  (cipher-set-key [_])
  (cipher-set-secret [_])
  (create-exchange [_ remote-id])
  (encrypt-message [_ session mbuf])
  (decrypt-message [_ session mbuf]))

(defn bytes->hex [#^bytes bytes]
  (Hex/encodeHexString bytes))

(defn hex->bytes [^String hex]
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

(defn make-n-bytes [bytes n]
  (let [actual-n (count bytes)]
    (if (< actual-n n)
      (byte-array (concat (repeat (- n actual-n) 0x00) bytes))
      (byte-array (take-last n bytes))
      )))

(defn- zeros* [n]
  (byte-array (repeat n 0x00)))

(def zeros (memoize zeros*))

(defn export-cipher-set [cs]
  {:key (bytes->hex (cipher-set-key cs))
   :secret (bytes->hex (cipher-set-secret cs))})

(defn import-cipher-set [load-fn {key-hex :key secret-hex :secret}]
  (let [key (hex->bytes key-hex)
        secret (hex->bytes secret-hex)]
    (load-fn secret key)) )
