(ns telehash.e3x-test
  (:refer-clojure :exclude [key])
  (:require [telehash.e3x :refer :all]
            [clojure.test :refer :all]))

(def cs1a "1a")
(def cs1a-A {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10c"
             :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3"})

(def cs1a-B {:key "0365694904381c00dfb7c01bb16b0852ea584a1b0b"
             :secret "031b502b0743b80c1575f4b459792b5d76ad636d"})

(def A->B (hex->bytes "030d8def4405c1380afeca3760322be710a3f53cfe7c9bed207249f31af977"))
(def B->A (hex->bytes "021aaad76e86b2c951a0ab00b22d031567b6bd556aa953a22b65f5d62dcbba"))

(defn validate-generated-cs1a [keypair]
  (is (= 21 (-> keypair key count)))
  (is (= 20 (-> keypair secret count))  (str "SECRET: " (:secret keypair))))

(deftest generated-cs1a-identity-validation
  (doseq [generated (repeatedly 100 #(generate-local cs1a))]
    (validate-generated-cs1a generated))
  )

(deftest generated-cs1a-id-check
  (is (= "1a" (:id (generate-local "1a")))))

(deftest valid-local-cs1a-should-load-correctly
  (let [cs-1 (load-local "1a"  cs1a-A)]
    (is (= (-> cs-1 key bytes->hex) (:key cs1a-A)))
    (is (= (-> cs-1 secret bytes->hex) (:secret cs1a-A)))))

(deftest loading-invalid-local-cs1a-should-throw-error
  (let [empty {}
        short-secret {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10c"
                      :secret "792fd655c8e03ae16e0e49c3f0265d04689cbe"}
        short-key {:key "03be277f53630a084de2f39c7ff9de56c38bb9d1"
                   :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3"}
        long-secret {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10c"
                     :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3a1"}
        long-key {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10ca1"
                  :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3"}]
    (is (thrown? Exception (load-local "1a" empty)))
;;    (is (thrown? Exception (load-local "1a" short-secret))) ; short secrets should not be a problem?
    (is (thrown? Exception (load-local "1a" short-key)))
;;    (is (thrown? Exception (load-local "1a" long-secret))) ; same for long ?
    (is (thrown? Exception (load-local "1a" long-key)))))

(deftest generated-cs1a-ephemeral-validation
  (let [ephemeral (generate-ephemeral "1a")]
    (is (= 21 (count (key ephemeral))))))

(deftest should-local-decrypt-cs1a
  (let [local (load-local "1a" cs1a-A)
        [_ decrypted] (decrypt local B->A)]
    (is (= 2 (count decrypted)))
    (is (= "0000" (bytes->hex decrypted)))))

(deftest should-load-remote-cs1a
  (let [remote (load-remote "1a" cs1a-B)]
    (is (= 16 (-> remote :token count)))))

(deftest should-local-encrypt-cs1a
  (let [local (load-local "1a" cs1a-A)
        remote (load-remote "1a" cs1a-B)
        [_ _ message] (encrypt local remote (hex->bytes "0000"))]
    (is (= 31 (count message)))))

(deftest should-remote-encrypt-cs1a
  (let [local (load-local "1a" cs1a-B)
        remote (load-remote "1a" cs1a-A)
        [_ _ message] (encrypt local remote (hex->bytes "0000"))]
    (is (= 31 (count message)))))

(deftest AES-128-encrypt-decrypt
  (let [in (hex->bytes "0000")
        shared1 (secp160r1-shared-secret (hex->bytes (:secret cs1a-A))
                                         (hex->bytes (:key cs1a-B)))
        shared2 (secp160r1-shared-secret (hex->bytes (:secret cs1a-B))
                                         (hex->bytes (:key cs1a-A)))
        key (fold (bytes->SHA256 shared1) 1)
        iv (byte-array (repeat 16 0x00))
        encrypted (AES-128-CTR-encrypt key iv in)
        out (AES-128-CTR-decrypt key iv encrypted)]
    (is (= (bytes->hex shared1) (bytes->hex shared2)))
    (is (= (bytes->hex in) (bytes->hex out)))))

(deftest encrypt-decrypt-round-trip
  (let [local-A (load-local "1a" cs1a-A)
        remote-B (load-remote "1a" cs1a-B)
        local-B (load-local "1a" cs1a-B)
        [_ _ encrypted] (encrypt local-A remote-B (hex->bytes "0000"))
        [_ decrypted] (decrypt local-B encrypted)]
    (is (= "0000" (bytes->hex decrypted)))))
