(ns telehash.lob-enc-test
  (:require [telehash.lob-enc :refer :all]
            [clojure.test :refer :all]))

(def ^:const byte-array-type (type (byte-array 0)))
(defn- byte-array? [o]
  (= (type o) byte-array-type))

(deftest lob-encode-testing
  (testing "lob-encode"
    (testing "should encode"
      (let [json "{\"type\":\"test\",\"foo\":[\"bar\"]}"
            body (->> "any binary!" (map byte) byte-array)
            bin  (lob-encode json body)]
        (is (= true (byte-array? bin)))
        (is (= 42 (count bin)))))))
