(ns telehash.e3x
  (:refer-clojure :exclude [key])
  (:require [telehash.byte-utils :as bu]))

;; This should be somewhere in the core?
(java.security.Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defrecord E3X [cs session])

(defprotocol CipherSet
  (cipher-set-id [_])
  (cipher-set-key [_])
  (cipher-set-secret [_])
  (create-exchange [_ remote-id])
  (encrypt-message [_ session mbuf])
  (decrypt-message [_ session mbuf])
  (verify-message [_ session mbuf]))

(defn export-cipher-set [cs]
  {:key (bu/bytes->hex (cipher-set-key cs))
   :secret (bu/bytes->hex (cipher-set-secret cs))})

(defn import-cipher-set [load-fn {key-hex :key secret-hex :secret}]
  (let [key (bu/hex->bytes key-hex)
        secret (bu/hex->bytes secret-hex)]
    (load-fn secret key)) )
