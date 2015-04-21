(ns telehash.hashname
  (:require [telehash.hashname.base32 :as base32])
  (:import  [org.apache.commons.codec.binary Hex]
            [org.apache.commons.codec.digest DigestUtils]))

(defn from-hex [hex]
  (try
    (-> hex char-array Hex/decodeHex)
    (catch Exception e
      (byte-array []))))

(def from-hex-k-t
  (map (fn [[k v]]
         [(from-hex k) v])))

(def digest-v-t
  (map (fn [[k v]]
         [k (-> v
                base32/decode
                DigestUtils/sha256)])))

(def base32-encode-v-t
  (map (fn [[k v]]
         [k (base32/encode v)])))

(defn intermediates [keys-map]
  (into (sorted-map)
        (comp digest-v-t base32-encode-v-t)
        keys-map))

(defn rollup-t
  ([] (byte-array []))
  ([current] (base32/encode current))
  ([current next] (-> (concat current next)
                      byte-array
                      DigestUtils/sha256)))

(defn from-keys [keys-map]
  {:pre [(map? keys-map)
         (not-empty keys-map)]}
  (transduce
   (comp from-hex-k-t
         digest-v-t
         (mapcat identity))
   rollup-t
   (into (sorted-map) keys-map)))
