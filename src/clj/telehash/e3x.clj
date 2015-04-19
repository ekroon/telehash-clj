(ns telehash.e3x
  (:refer-clojure :exclude [key])
  (:import [java.security KeyPairGenerator SecureRandom]
           [org.bouncycastle.asn1.sec SECNamedCurves]
           [org.bouncycastle.crypto AsymmetricCipherKeyPair]
           [org.bouncycastle.crypto.generators ECKeyPairGenerator]
           [org.bouncycastle.crypto.params ECPublicKeyParameters ECPrivateKeyParameters
            ECDomainParameters ECKeyGenerationParameters]
           [org.apache.commons.codec.binary Hex]))

(defmulti generate-cs identity)
(defmulti load-cs (fn [id _] id))
(defmulti key :id)
(defmulti secret :id)

(java.security.Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.))

(def ^:static secp160r1-curve (SECNamedCurves/getByName "secp160r1"))
(def ^:static secp160r1-domain
  (ECDomainParameters. (.getCurve secp160r1-curve)
                       (.getG secp160r1-curve)
                       (.getN secp160r1-curve)
                       (.getH secp160r1-curve)))

(defn- generator [domain]
  (let [generator (ECKeyPairGenerator.)
        params (ECKeyGenerationParameters. domain (SecureRandom.))]
    (.init generator params)
    generator))

(defn make-n-bytes [bytes n]
  (let [actual-n (count bytes)]
    (if (< actual-n n)
      (byte-array (concat (repeat (- n actual-n) 0x00) bytes))
      (byte-array (take-last n bytes)))))

(defmethod generate-cs "1a" [cs]
  (let [generator (generator secp160r1-domain)
        keypair (.generateKeyPair generator)]
    {:id "1a" :keypair keypair}))

(defmethod load-cs "1a" [_ {:keys [key secret]}]
  (let [public (Hex/decodeHex (char-array key))
        public-Q (-> (.getCurve secp160r1-curve) (.decodePoint public))
        public-params (ECPublicKeyParameters. public-Q secp160r1-domain)
        private (Hex/decodeHex (char-array secret))
        private-D (BigInteger. private)
        private-params (ECPrivateKeyParameters. private-D secp160r1-domain)
        keypair (AsymmetricCipherKeyPair. public-params private-params)]
    {:id "1a" :keypair keypair})
  )

(defmethod key "1a" [cs]
  (-> (:keypair cs) .getPublic .getQ (.getEncoded true) Hex/encodeHexString))

(defmethod secret "1a" [cs]
  (-> (:keypair cs) .getPrivate .getD .toByteArray
                    (make-n-bytes 20) Hex/encodeHexString))
