(ns telehash.lob-enc
  (:import java.io.ByteArrayOutputStream
           java.io.DataOutputStream))

(defn lob-encode [json body]
  (let [json-array (->> json (map byte) byte-array)
        output-stream (ByteArrayOutputStream.)
        data-output (DataOutputStream. output-stream)]
    (do
      (.writeChar data-output (count json-array))
      (.write data-output json-array)
      (.write data-output body)
      (.toByteArray output-stream))))
