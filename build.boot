(def VERSION "0.0.1-SNAPSHOT")

(set-env! :dependencies '[[leiningen-core "2.5.0"]])
(require '[leiningen.core.project :refer [defproject]])

(eval (read-string (slurp "project.clj")))


(set-env!
 :source-paths   (merge (set (:source-paths project)) "test/clj")
 :resource-paths (set (:resource-paths project))
 :dependencies   (into '[[adzerk/boot-test "1.0.4" :scope "test"]]
                       (:dependencies project)))

(require '[adzerk.boot-test :refer :all])
