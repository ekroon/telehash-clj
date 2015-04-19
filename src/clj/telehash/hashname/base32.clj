(ns telehash.hashname.base32
  (:import org.apache.commons.codec.binary.Base32)
  (:require [clojure.string :as str]))


(defn- padding-calculated [bytes]
  (let [bits   (* 8 (count bytes))
        m40    (mod bits 40)
        pad    (if (= 0 m40) 0 (- 40 m40))
        result (quot pad 5)]
    result))

(defn- padding [bytes]
  (let [lookup [0 6 4 3 1]]
    (nth lookup (mod (count bytes) 5))))

(defn encode [bytes]
  (let
      [encoder (Base32.)
       encoded-length (.. encoder (getEncodedLength bytes))
       unpadded-length (- encoded-length (padding bytes))]
    (->
     (.. (Base32.)
         (encodeToString bytes)
         (toLowerCase)
         (substring 0 unpadded-length)))))

(defn decode [base32string]
  (->> base32string
       (.toUpperCase)
       (.decode (Base32.))))
