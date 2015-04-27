(ns telehash.random
  (:refer-clojure :exclude [bytes int])
  (:import java.security.SecureRandom))

(defn bytes
  "Returns a random byte array of the specified size."
  [size]
  (let [seed (byte-array size)]
    (.nextBytes (SecureRandom.) seed)
    seed))

(defn int []
  (clojure.core/int (clojure.lang.BigInt/fromBigInteger (BigInteger. (bytes 4)))))
