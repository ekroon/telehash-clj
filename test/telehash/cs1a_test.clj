(ns telehash.cs1a-test
  (:refer-clojure :exclude [key load import])
  (:require [telehash.cs1a :refer :all]
            [telehash.byte-utils :as bu]
            [telehash.e3x :as e3x]
            [clojure.test :refer :all]))

(def cs1a "1a")
(def cs1a-A {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10c"
             :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3"})

(def cs1a-B {:key "0365694904381c00dfb7c01bb16b0852ea584a1b0b"
             :secret "031b502b0743b80c1575f4b459792b5d76ad636d"})

(def A->B (bu/hex->bytes "030d8def4405c1380afeca3760322be710a3f53cfe7c9bed207249f31af977"))
(def B->A (bu/hex->bytes "021aaad76e86b2c951a0ab00b22d031567b6bd556aa953a22b65f5d62dcbba"))
(def faulty-B->A (bu/hex->bytes "021aaad76e86b2c951a0ab00b22d031567b6bd556aa953a22b65f5d62dcbbb"))

(def import (partial e3x/import-cipher-set load))

(defn create-exchange [cs remote]
  (e3x/create-exchange cs (bu/hex->bytes (:key remote))))

(defn validate-generated [keypair]
  (is (= 21 (-> keypair e3x/cipher-set-key count)))
  (is (= 20 (-> keypair e3x/cipher-set-secret count))  (str "SECRET: " (:secret keypair))))

(deftest generated-identity-validation
  (doseq [generated (repeatedly 100 #(generate))]
    (validate-generated generated))
  )

(deftest generated-id-check
  (is (= "1a" (e3x/cipher-set-id (generate)))))

(deftest valid-local-should-load-correctly
  (let [cs-1 (import  cs1a-A)]
    (is (= (-> cs-1 e3x/cipher-set-key bu/bytes->hex) (:key cs1a-A)))
    (is (= (-> cs-1 e3x/cipher-set-secret bu/bytes->hex) (:secret cs1a-A)))))

(deftest loading-invalid-local-should-throw-error
  (let [empty {}
        short-secret {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10c"
                      :secret "792fd655c8e03ae16e0e49c3f0265d04689cbe"}
        short-key {:key "03be277f53630a084de2f39c7ff9de56c38bb9d1"
                   :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3"}
        long-secret {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10c"
                     :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3a1"}
        long-key {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10ca1"
                  :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3"}]
    (is (thrown? Exception (import empty)))
;;    (is (thrown? Exception (load-local "1a" short-secret))) ; short secrets should not be a problem?
    (is (thrown? Exception (import short-key)))
;;    (is (thrown? Exception (load-local "1a" long-secret))) ; same for long ?
    (is (thrown? Exception (import long-key)))))

(deftest should-local-decrypt
  (let [local (import cs1a-A)
        exchange (create-exchange local cs1a-B)
        [_ decrypted] (e3x/decrypt-message local (:session exchange) B->A)]
    (is (= 2 (count decrypted)))
    (is (= "0000" (bu/bytes->hex decrypted)))))

(deftest should-verify
  (let [local (import cs1a-A)
        exchange (create-exchange local cs1a-B)
        valid? (e3x/verify-message local (:session exchange) B->A)]
    (is (= true valid?))))

(deftest should-invalidate
  (let [local (import cs1a-A)
        exchange (create-exchange local cs1a-B)
        valid? (e3x/verify-message local (:session exchange) faulty-B->A)]
    (is (= false valid?))))

(deftest should-create-exchange
  (let [local (generate)
        exchange (create-exchange local cs1a-B)]
    (is (= 21 (-> exchange :session :endpoint count)))))

(deftest should-local-encrypt
  (let [local (import cs1a-A)
        exchange (create-exchange local cs1a-B)
        [_ message] (e3x/encrypt-message local (:session exchange) (bu/hex->bytes "0000"))]
    (is (= 31 (count message)))))

(deftest should-remote-encrypt
  (let [local (import cs1a-B)
        exchange (create-exchange local cs1a-A)
        [_ message] (e3x/encrypt-message local (:session exchange) (bu/hex->bytes "0000"))]
    (is (= 31 (count message)))))

;; (deftest AES-128-encrypt-decrypt
;;   (let [in (hex->bytes "0000")
;;         shared1 (secp160r1-shared-secret (hex->bytes (:secret cs1a-A))
;;                                          (hex->bytes (:key cs1a-B)))
;;         shared2 (secp160r1-shared-secret (hex->bytes (:secret cs1a-B))
;;                                          (hex->bytes (:key cs1a-A)))
;;         key (fold (bytes->SHA256 shared1) 1)
;;         iv (byte-array (repeat 16 0x00))
;;         encrypted (AES-128-CTR-encrypt key iv in)
;;         out (AES-128-CTR-decrypt key iv encrypted)]
;;     (is (= (bytes->hex shared1) (bytes->hex shared2)))
;;     (is (= (bytes->hex in) (bytes->hex out)))))

(deftest encrypt-decrypt-round-trip
  (let [local-A (import cs1a-A)
        exchange-A (create-exchange local-A cs1a-B)
        local-B (import cs1a-B)
        exchange-B (create-exchange local-B cs1a-A)
        [_ encrypted] (e3x/encrypt-message local-A (:session exchange-A) (bu/hex->bytes "4242"))
        valid? (e3x/verify-message local-B (:session exchange-B) encrypted)
        [_ decrypted] (e3x/decrypt-message local-B (:session exchange-B) encrypted)]
    (is (= true valid?))
    (is (= "4242" (bu/bytes->hex decrypted)))))

(deftest should-create-channel
  (let [local (import cs1a-A)
        exchange (create-exchange local cs1a-B)
        channel (e3x/create-channel local (:session exchange) B->A)]
    (is (= 16 (-> channel :local-token count)))))

(deftest should-encrypt-channel-message
  (let [local (import cs1a-A)
        exchange (create-exchange local cs1a-B)
        channel (e3x/create-channel local (:session exchange) B->A)
        [_ message] (e3x/encrypt-channel-message local channel (bu/hex->bytes "0000"))
        ]
    (is (= 10 (count message)))))

(deftest full-channel-test
  (let [local-A (import cs1a-A)
        exchange-A (create-exchange local-A cs1a-B)
        local-B (import cs1a-B)
        exchange-B (create-exchange local-B cs1a-A)
        [_ A->B] (e3x/encrypt-message local-A (:session exchange-A) (bu/hex->bytes "0000"))
        [_ B->A] (e3x/encrypt-message local-B (:session exchange-B) (bu/hex->bytes "0000"))
        channel-BA (e3x/create-channel local-B (:session exchange-B) A->B)
        channel-AB (e3x/create-channel local-A (:session exchange-A) B->A)
        [_ encrypted] (e3x/encrypt-channel-message local-A channel-AB (bu/hex->bytes "4242"))
        [_ decrypted] (e3x/decrypt-channel-message local-B channel-BA encrypted)
        ]
    (is (= "4242" (bu/bytes->hex decrypted)))))
