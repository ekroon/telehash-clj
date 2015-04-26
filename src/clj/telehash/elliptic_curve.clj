(ns telehash.elliptic-curve
  (:import [java.security SecureRandom]
           [org.bouncycastle.asn1.sec SECNamedCurves]
           [org.bouncycastle.crypto.agreement ECDHBasicAgreement]
           [org.bouncycastle.crypto.generators ECKeyPairGenerator]
           [org.bouncycastle.crypto.params ECPublicKeyParameters ECPrivateKeyParameters
            ECDomainParameters ECKeyGenerationParameters]))

(defprotocol EllipticCurve
  "Elliptic curve implementation."
  (private-key [_] "Returns the private key as byte-array")
  (public-key [_] "Returns the public key as byte-array")
  (calculate-shared-secret [_ other-public-key]))

(defn- load-private [domain bytes]
  (let [D (BigInteger. bytes)]
    (ECPrivateKeyParameters. D domain)))

(defn- load-public [domain bytes]
  (let [Q (-> (.getCurve domain) (.decodePoint bytes))]
    (ECPublicKeyParameters. Q domain)))

(defn- bouncy-private->bytes [private]
  (.toByteArray (.getD private)))

(defn- bouncy-public->bytes [public]
  (.getEncoded (.getQ public) true))

(deftype BouncyEllipticCurve [name domain private-key public-key agreement]
  clojure.lang.Named
  (getName [_] name)
  EllipticCurve
  (private-key [_] (bouncy-private->bytes private-key))
  (public-key [_] (bouncy-public->bytes public-key))
  (calculate-shared-secret [_ other-public-key]
    (let [bouncy-public (load-public domain other-public-key)]
      (-> (.calculateAgreement agreement bouncy-public)
          .toByteArray))))

(def ^:static secp160r1-curve (SECNamedCurves/getByName "secp160r1"))
(def ^:static secp160r1-domain
  (ECDomainParameters. (.getCurve secp160r1-curve)
                       (.getG secp160r1-curve)
                       (.getN secp160r1-curve)
                       (.getH secp160r1-curve)))

(defn- keypair-generator [domain]
  (let [generator (ECKeyPairGenerator.)
        params (ECKeyGenerationParameters. domain (SecureRandom.))]
    (.init generator params)
    generator))

(defn- create-agreement [domain private]
  (let [agreement (ECDHBasicAgreement.)]
    (.init agreement private)
    agreement))

(defn generate-secp160r1 []
  (let [generator (keypair-generator secp160r1-domain)]
    (loop [keypair (.generateKeyPair generator)]
      (if (not= 20 (count (bouncy-private->bytes (.getPrivate keypair))))
        (recur (.generateKeyPair generator))
        (->BouncyEllipticCurve "secp160r1" secp160r1-domain
                               (.getPrivate keypair) (.getPublic keypair)
                               (create-agreement secp160r1-domain (.getPrivate keypair)))))))

(defn load-secp160r1 [private public]
  (let [private-key (load-private secp160r1-domain private)
        public-key (load-public secp160r1-domain public)]
    (->BouncyEllipticCurve "secp160r1" secp160r1-domain
                           private-key public-key
                           (create-agreement secp160r1-domain private-key))))
