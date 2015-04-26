(ns telehash.SHA
  (:import [org.bouncycastle.crypto.digests SHA256Digest]
           [org.bouncycastle.crypto.params KeyParameter]
           [org.bouncycastle.crypto.macs HMac]
           [org.bouncycastle.jcajce.provider.digest SHA256$Digest]))

(defn bytes->SHA256 [#^bytes bytes]
  (let [digester (SHA256$Digest.)]
    (.engineUpdate digester bytes 0 (count bytes))
    (.engineDigest digester)))

(defn HMAC-SHA256 [key & values]
  (let [hmac (HMac. (SHA256Digest.))
        result (byte-array 32)]
    (.init hmac (KeyParameter. key))
    (doseq [v values]
      (.update hmac v 0 (count v)))
    (.doFinal hmac result 0)
    result))
