(ns telehash.SHA
  (:require [telehash.byte-utils :as bu])
  (:import [org.bouncycastle.crypto.digests SHA256Digest]
           [org.bouncycastle.crypto.params KeyParameter]
           [org.bouncycastle.crypto.macs HMac]
           [org.bouncycastle.jcajce.provider.digest SHA256$Digest]))

(defn words->SHA256 [word-seq]
  (let [digester (SHA256$Digest.)]
    (doseq [w word-seq]
      (.engineUpdate digester (bu/ensure-byte-array w) 0 (count w)))
    (.engineDigest digester)))

(defn bytes->SHA256 [bytes-or-seq]
  (let [bytes (bu/ensure-byte-array bytes-or-seq)
        digester (SHA256$Digest.)]
    (.engineUpdate digester bytes 0 (count bytes))
    (.engineDigest digester)))

(defn HMAC-SHA256 [key & values]
  (let [hmac (HMac. (SHA256Digest.))
        result (byte-array 32)]
    (.init hmac (KeyParameter. (bu/ensure-byte-array key)))
    (doseq [v values]
      (.update hmac (bu/ensure-byte-array v) 0 (count v)))
    (.doFinal hmac result 0)
    result))
