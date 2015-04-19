(ns telehash.e3x-test
  (:require [telehash.e3x :refer :all]
            [clojure.test :refer :all]))

(def cs1a {:id "1a"})

(defn validate-generated-cs1a [keypair]
  (is (= 42 (-> keypair :key count)))
  (is (= 40 (-> keypair :secret count))  (str "SECRET: " (:secret keypair))))

(deftest generate-cs1a
  (doseq [generated (repeatedly 100 #(generate cs1a))]
    (validate-generated-cs1a generated))
  )
