(ns telehash.hashname
  (:require [telehash.hashname.base32 :as base32])
  (:import  [org.apache.commons.codec.binary Hex]
            [org.apache.commons.codec.digest DigestUtils]))

(defn from-hex [hex]
  (try
    (-> hex char-array Hex/decodeHex)
    (catch Exception e
      (byte-array []))))

(defn rollup [current next]
  (-> (concat current next)
      byte-array
      DigestUtils/sha256))

(defn- to-vector [map]
  (->> map
       (into (sorted-map))
       (mapcat (fn [[k v]] [(from-hex k)
                           (DigestUtils/sha256 (base32/decode v))]))
       (into [])))

(defn from-keys [keys-map]
  {:pre [(map? keys-map)
         (not-empty keys-map)]}
  (->> keys-map
       to-vector
       (reduce rollup (byte-array []))
       base32/encode))
