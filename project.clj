(defproject clj-telehash "0.0.1-SNAPSHOT"
            :description ""
            :url ""
            :license {:name "Eclipse Public License"
                      :url "http://www.eclipse.org/legal/epl-v10.html"}
            :source-paths ["src/clj"]
            :resource-paths  ["src/clj" "src/resources"]
            :dependencies [[org.clojure/clojure "1.7.0-beta1"]
                           [commons-codec "1.10"]
                           [org.bouncycastle/bcprov-jdk15on "1.52"]])