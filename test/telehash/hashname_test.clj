(ns telehash.hashname-test
  (:require [telehash.hashname :refer :all]
            [clojure.test :refer :all]))

(deftest test-hashname-generation
  (testing "hashname"
    (testing "should generate from two keys in order"
      (let [keys {"3a" "hp6yglmmqwcbw5hno37uauh6fn6dx5oj7s5vtapaifrur2jv6zha"
                  "1a" "vgjz3yjb6cevxjomdleilmzasbj6lcc7"}]
        (is (= "jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3mqnvxafb26rqllwa"
               (from-keys keys)))))

    (testing "should generate from one key"
      (let [keys {"1a" "vgjz3yjb6cevxjomdleilmzasbj6lcc7"}]
        (is (= "echmb6eke2f6z2mqdwifrt6i6hkkfua7hiisgrms6pwttd6jubiq"
               (from-keys keys)))))

    (testing "intermediates"
      (let [keys {"3a" "hp6yglmmqwcbw5hno37uauh6fn6dx5oj7s5vtapaifrur2jv6zha"
                  "1a" "vgjz3yjb6cevxjomdleilmzasbj6lcc7"}]
        (is (= {"1a" "ym7p66flpzyncnwkzxv2qk5dtosgnnstgfhw6xj2wvbvm7oz5oaq"
                "3a" "bmxelsxgecormqjlnati6chxqua7wzipxliw5le35ifwxlge2zva"}
               (intermediates keys)))))))
