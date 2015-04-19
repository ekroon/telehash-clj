(ns telehash.e3x-test
  (:refer-clojure :exclude [key])
  (:require [telehash.e3x :refer :all]
            [clojure.test :refer :all]))

(def cs1a "1a")
(def cs1a-test-1 {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10c"
                  :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3"})

(def cs1a-test-2 {:key "0365694904381c00dfb7c01bb16b0852ea584a1b0b"
                  :secret "031b502b0743b80c1575f4b459792b5d76ad636d"})

(defn validate-generated-cs1a [keypair]
  (is (= 42 (-> keypair key count)))
  (is (= 40 (-> keypair secret count))  (str "SECRET: " (:secret keypair))))

(deftest generated-cs1a-key-secret-validation
  (doseq [generated (repeatedly 100 #(generate-cs cs1a))]
    (validate-generated-cs1a generated))
  )

(deftest generated-cs1a-id-check
  (is (= "1a" (:id (generate-cs "1a")))))

(deftest valid-cs1a-should-load-correctly
  (let [cs-1 (load-cs "1a"  cs1a-test-1)
        cs-2 (load-cs "1a" cs1a-test-2)]
    (is (= (key cs-1) (:key cs1a-test-1)))
    (is (= (secret cs-1) (:secret cs1a-test-1)))
    (is (= (key cs-2) (:key cs1a-test-2)))
    (is (= (secret cs-2) (:secret cs1a-test-2)))))

(deftest loading-invalid-cs1a-should-throw-error
  (let [empty {}
        short-secret {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10c"
                      :secret "792fd655c8e03ae16e0e49c3f0265d04689cbe"}
        short-key {:key "03be277f53630a084de2f39c7ff9de56c38bb9d1"
                   :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3"}
        long-secret {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10c"
                     :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3a1"}
        long-key {:key "03be277f53630a084de2f39c7ff9de56c38bb9d10ca1"
                  :secret "792fd655c8e03ae16e0e49c3f0265d04689cbea3"}]
    (is (thrown? Exception (load-cs "1a" empty)))
    (is (thrown? Exception (load-cs "1a" short-secret)))
    (is (thrown? Exception (load-cs "1a" short-key)))
    (is (thrown? Exception (load-cs "1a" long-secret)))
    (is (thrown? Exception (load-cs "1a" long-key)))))
