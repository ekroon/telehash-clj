(ns telehash.e3x
  (:import [java.security KeyPairGenerator SecureRandom]
           [org.bouncycastle.asn1.sec SECNamedCurves]
           [org.bouncycastle.crypto.generators ECKeyPairGenerator]
           [org.bouncycastle.crypto.params ECDomainParameters ECKeyGenerationParameters]
           [org.bouncycastle.jcajce.provider.asymmetric.ec BCECPublicKey]
           [org.bouncycastle.jce.spec ECParameterSpec]
           [org.apache.commons.codec.binary Hex]))

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

(defmulti generate :id)

(defn make-n-bytes [bytes n]
  (let [actual-n (count bytes)]
    (if (< actual-n n)
      (byte-array (concat (repeat (- n actual-n) 0x00) bytes))
      (byte-array (take-last n bytes)))))

(defmethod generate "1a" [cs]
  (let [generator (generator secp160r1-domain)
        keypair (.generateKeyPair generator)
        private (-> keypair .getPrivate .getD .toByteArray
                    (make-n-bytes 20) Hex/encodeHexString)
        public (-> keypair .getPublic .getQ (.getEncoded true) Hex/encodeHexString)]
    {:key public
     :secret private})
  )
