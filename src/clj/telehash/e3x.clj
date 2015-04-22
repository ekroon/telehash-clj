(ns telehash.e3x
  (:refer-clojure :exclude [key])
  (:import [java.nio ByteBuffer]
           [java.security SecureRandom]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec IvParameterSpec]
           [org.apache.commons.codec.binary Hex]
           [org.bouncycastle.asn1.sec SECNamedCurves]
           [org.bouncycastle.crypto AsymmetricCipherKeyPair]
           [org.bouncycastle.crypto.agreement ECDHBasicAgreement]
           [org.bouncycastle.crypto.digests SHA256Digest]
           [org.bouncycastle.crypto.generators ECKeyPairGenerator]
           [org.bouncycastle.crypto.macs HMac]
           [org.bouncycastle.crypto.params ECPublicKeyParameters ECPrivateKeyParameters
            ECDomainParameters ECKeyGenerationParameters KeyParameter]
           [org.bouncycastle.jcajce.provider.digest SHA256$Digest SHA256$HashMac]))

(java.security.Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(defmulti generate-local identity)
(defmulti load-local (fn [cs-id _] cs-id))
(defmulti generate-ephemeral identity)
(defmulti load-remote (fn [cs-id _] cs-id))
(defmulti key :id)
(defmulti secret :id)

(defmulti decrypt (fn [local msg] (:id local)))
(defmulti encrypt (fn [local remote msg] (:id local)))

(defn bytes->hex [#^bytes bytes]
  (Hex/encodeHexString bytes))

(defn hex->bytes [^String hex]
  (Hex/decodeHex (char-array hex)))

(defn int->bytes [x]
  (let [buffer (ByteBuffer/allocate 4)]
    (.putInt buffer x)
    (.array buffer)))

(defn bytes->SHA256 [#^bytes bytes]
  (let [digester (SHA256$Digest.)]
    (.engineUpdate digester bytes 0 (count bytes))
    (.engineDigest digester)))

(defn HMAC-SHA256 [key & values]
  (let [hmac (HMac. (SHA256Digest.))
        result (byte-array 32)]
    (.init hmac (KeyParameter. key))
    (doseq [v values]
      (.update hmac v 0 (count v)))
    (.doFinal hmac result 0)
    result))

(defn AES-128-CTR-encrypt [keybuf ivbuf #^bytes bytes]
  (let [cipher (Cipher/getInstance "AES/CTR/NoPadding")
        key (SecretKeySpec. keybuf "AES")
        iv (IvParameterSpec. ivbuf)]
    (.init cipher Cipher/ENCRYPT_MODE key iv)
    (.doFinal cipher bytes)))

(defn AES-128-CTR-decrypt [keybuf ivbuf #^bytes bytes]
  (let [cipher (Cipher/getInstance "AES/CTR/NoPadding")
        key (SecretKeySpec. keybuf "AES")
        iv (IvParameterSpec. ivbuf)]
    (.init cipher Cipher/DECRYPT_MODE key iv)
    (.doFinal cipher bytes)))

(defn fold
  ([bytes] (fold bytes 1))
  ([bytes n]
   (if (or (>= 0 n) ((complement even?) (count bytes))) bytes
       (let [[p1 p2] (split-at (/ (count bytes) 2) bytes)
             folded (byte-array (map bit-xor p1 p2))]
         (recur folded (- n 1))))))

(def ^:static secp160r1-curve (SECNamedCurves/getByName "secp160r1"))
(def ^:static secp160r1-domain
  (ECDomainParameters. (.getCurve secp160r1-curve)
                       (.getG secp160r1-curve)
                       (.getN secp160r1-curve)
                       (.getH secp160r1-curve)))

(defn keypair-generator [domain]
  (let [generator (ECKeyPairGenerator.)
        params (ECKeyGenerationParameters. domain (SecureRandom.))]
    (.init generator params)
    generator))

(defn make-n-bytes [bytes n]
  (let [actual-n (count bytes)]
    (if (< actual-n n)
      (byte-array (concat (repeat (- n actual-n) 0x00) bytes))
      (byte-array (take-last n bytes))
      )))

(defn load-private-secp160r1 [private]
  (let [D (BigInteger. private)]
    (ECPrivateKeyParameters. D secp160r1-domain)))

(defn load-public-secp160r1 [public]
  (let [Q (-> (.getCurve secp160r1-curve) (.decodePoint public))]
    (ECPublicKeyParameters. Q secp160r1-domain)))

(defn secp160r1-shared-secret [private public]
;;  (println "calculate shared:" (bytes->hex private) (bytes->hex public))
  (let [Q (-> (.getCurve secp160r1-curve) (.decodePoint public))
        D (BigInteger. private)
        agreement (ECDHBasicAgreement.)]
    (.init agreement (ECPrivateKeyParameters. D secp160r1-domain))
    (-> (.calculateAgreement agreement (ECPublicKeyParameters. Q secp160r1-domain))
        .toByteArray (make-n-bytes 20))))

(defmethod generate-local "1a" [_]
  (let [generator (keypair-generator secp160r1-domain)
        keypair (.generateKeyPair generator)
        result {:id "1a" :public (.getPublic keypair) :private (.getPrivate keypair)}]
    (if (not= 20 (count (secret result)))
      (generate-local "1a")
      result)))

(defmethod load-local "1a" [_ {hex-key :key  hex-secret :secret}]
  (let [public (Hex/decodeHex (char-array hex-key))
        private (Hex/decodeHex (char-array hex-secret))
        private-key (load-private-secp160r1 private)
        public-key (load-public-secp160r1 public)
        result {:id "1a" :public public-key :private private-key}]
    (if-not (= hex-key (-> result key bytes->hex)) (throw (Exception. "invalid key")))
    (if-not (= hex-secret (-> result secret bytes->hex)) (throw (Exception. "invalid secret")))
    result)
  )

(defmethod generate-ephemeral "1a" [_]
  (let [remote (generate-local "1a")]
    remote))

(defmethod load-remote "1a" [_ {hex-key :key}]
  (let [endpoint (Hex/decodeHex (char-array hex-key))
        ephemeral (generate-ephemeral "1a")
        token (-> (key ephemeral) (make-n-bytes 16) bytes->SHA256 (make-n-bytes 16))
        seq (rand-int Integer/MAX_VALUE)]
    (-> ephemeral
        (assoc :endpoint endpoint)
        (assoc :token token)
        (assoc :seq seq))))

(defmethod key "1a" [cs]
  (-> (:public cs) .getQ (.getEncoded true)))

(defmethod secret "1a" [cs]
  (-> (:private cs) .getD .toByteArray))

(defn- bytes->1a-message [bytes]
  (if (< (count bytes) (+ 21 4 4)) nil
      (let [key (byte-array (take 21 bytes))
            iv (byte-array (->> bytes (drop 21) (take 4)))
            inner (byte-array (->> bytes (drop (+ 21 4)) (drop-last 4)))
            hmac (byte-array (->> bytes (take-last 4)))]
        {:key  key
         :iv iv
         :inner inner
         :hmac  hmac})))

(defonce ivz-12 (byte-array (repeat 12 0x00)))

(defmethod decrypt "1a" [local msgbuf]
  (if-let [message (bytes->1a-message msgbuf)]
    (let [shared-secret (secp160r1-shared-secret (secret local) (:key message))
          aes-key (fold (bytes->SHA256 shared-secret) 1)
 ;;         _ (println "decrypt:"  (bytes->hex shared-secret) (bytes->hex aes-key))
          padded-iv (byte-array (concat (:iv message) ivz-12))
          decrypted (AES-128-CTR-decrypt aes-key padded-iv (:inner message))]
      [local decrypted])
    [local nil]))

(defmethod encrypt "1a" [local remote msgbuf]
  (let [{:keys [endpoint]} remote
        shared-secret (secp160r1-shared-secret (secret remote) endpoint)
        aes-key (fold (bytes->SHA256 shared-secret) 1)
 ;;       _ (println "encrypt:" (bytes->hex shared-secret) (bytes->hex aes-key))
        new-seq (inc (:seq remote))
        iv (int->bytes new-seq)
        padded-iv (byte-array (concat iv ivz-12))
        encrypted (AES-128-CTR-encrypt aes-key padded-iv msgbuf)
        mac-secret (secp160r1-shared-secret (secret local) endpoint)
        macd (byte-array (concat (key remote) iv encrypted))
        hmac (fold (HMAC-SHA256 (byte-array (concat mac-secret iv)) macd) 3)]
    [(assoc local :seq new-seq)
     remote
     (byte-array (concat macd hmac))]))
