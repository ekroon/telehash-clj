(ns telehash.hashname.base32-test
  "Short package description."
  (:require [clojure.test :refer :all]
            [telehash.hashname.base32 :as base32]))

(deftest encode
  (is (= "mzxw6ytboi"
         (base32/encode (byte-array (map byte "foobar"))))))
(deftest decode
  (is (= "foobar"
         (clojure.string/join
          (map char
               (base32/decode "mzxw6ytboi"))))))
