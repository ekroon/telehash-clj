(def VERSION "0.0.1-SNAPSHOT")

(set-env! :dependencies '[[leiningen-core "2.5.0"]])
(use 'leiningen.core.project)

(eval (read-string (slurp "project.clj")))

(set-env!
 :source-paths   (set (:source-paths project))
 :resource-paths (set (:resource-paths project))
 :dependencies   (into [] (:dependencies project)))
