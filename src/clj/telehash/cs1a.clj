(ns telehash.cs1a
  (:refer-clojure :exclude [load])
  (:require [telehash.e3x :as e3x]
            [telehash.byte-utils :as bu]
            [telehash.random :as random]
            [telehash.SHA :as sha]
            [telehash.AES :as aes]
            [telehash.elliptic-curve :as ec])
  (:import telehash.e3x.CipherSet))

(defn- create-exchange* [local remote-id]
  (let [ephemeral (ec/generate-secp160r1)
        seq (rand-int Integer/MAX_VALUE)
        encrypt-key (-> (ec/calculate-shared-secret ephemeral remote-id)
                           (sha/bytes->SHA256)
                           (bu/fold 1))
        mac-secret (ec/calculate-shared-secret local remote-id)]
    {:endpoint remote-id
     :ephemeral ephemeral
     :seq (random/int)
     :encrypt-key encrypt-key
     :mac-secret mac-secret}))

(defn- encrypt-message* [local session msgbuf]
  "local secp"
  (let [{:keys [endpoint ephemeral seq encrypt-key mac-secret]} session
        new-seq (inc seq)
        iv (bu/int->bytes new-seq)
        padded-iv (byte-array (concat iv (bu/zeros 12)))
        encrypted (aes/AES-128-CTR-encrypt encrypt-key padded-iv msgbuf)
        macd (concat (ec/public-key ephemeral) iv encrypted)
        hmac (bu/fold (sha/HMAC-SHA256 (concat mac-secret iv) macd) 3)]
    [(assoc session :seq new-seq)
     (byte-array (concat macd hmac))]))

(defn- bytes->message [bytes]
  (if (< (count bytes) (+ 21 4 4)) nil
      (let [key (take 21 bytes)
            iv (->> bytes (drop 21) (take 4))
            inner (->> bytes (drop (+ 21 4)) (drop-last 4))
            macd (->> bytes (drop-last 4))
            hmac (->> bytes (take-last 4))]
        {:key  key
         :iv iv
         :inner inner
         :macd macd
         :hmac hmac})))

(defn- decrypt-message* [secp160r1 msgbuf]
  (if-let [message (bytes->message msgbuf)]
    (let [shared-secret (ec/calculate-shared-secret secp160r1 (:key message))
          aes-key (bu/fold (sha/bytes->SHA256 shared-secret) 1)
          padded-iv (byte-array (concat (:iv message) (bu/zeros 12)))
          decrypted (aes/AES-128-CTR-decrypt aes-key padded-iv (:inner message))]
      decrypted)
    nil))

(defn- verify-message* [secp160r1 session msgbuf]
  (if-let [message (bytes->message msgbuf)]
    (let [secret (:mac-secret session)
          iv (:iv message)
          check-mac (bu/fold (sha/HMAC-SHA256 (concat secret iv) (:macd message)) 3)]
      (= (bu/bytes->hex check-mac) (bu/bytes->hex (:hmac message))))
    false))

(defn- create-channel* [session mbuf]
  (let [;; Routing-Token for channel is first 16 bytes of SHA256 of first 16 bytes of message body.
        ;; Which means 16 bytes of SHA256 of first 16 bytes of public ephemeral
        ephemeral (:ephemeral session)
        local-token  (-> ephemeral
                          (ec/public-key) (bu/take-n 16)
                          (sha/bytes->SHA256) (bu/take-n 16) (bu/ensure-byte-array))
        remote-token (-> mbuf (bu/take-n 16)
                         (sha/bytes->SHA256) (bu/take-n 16) (bu/ensure-byte-array))
        received-key (bu/take-n mbuf 21)
        shared-secret (ec/calculate-shared-secret ephemeral received-key)
        encryption-key (bu/fold (sha/words->SHA256
                                 [shared-secret (ec/public-key ephemeral) received-key]) 1)
        decryption-key (bu/fold (sha/words->SHA256
                                 [shared-secret received-key (ec/public-key ephemeral)]))
        ]
    {:local-token local-token
     :remote-token remote-token
     :encryption-key encryption-key
     :decryption-key decryption-key
     :seq (random/int)
     }))

(defn- encrypt-channel-message* [channel mbuf]
  (let [new-seq (inc (:seq channel))
        iv (bu/int->bytes new-seq)
        encrypted (aes/AES-128-CTR-encrypt (:encryption-key channel) (bu/right-zero-padded iv 16) mbuf)
        mac-key (concat (:encryption-key channel) iv)
        hmac (bu/fold (sha/HMAC-SHA256 mac-key encrypted) 3)]
    [(assoc channel :seq new-seq)
     (bu/ensure-byte-array (concat iv encrypted hmac))]))

(defn- decrypt-channel-message* [channel mbuf]
  (let [seq (take 4 mbuf)
        inner (drop-last 4 (drop 4 mbuf))
        hmac (take-last 4 mbuf)
        mac-key (concat (:decryption-key channel) seq)
        check-mac (bu/fold (sha/HMAC-SHA256 mac-key inner) 3)]
    (if (not= (bu/bytes->hex hmac) (bu/bytes->hex check-mac))
      [channel nil]
      (let [decrypted (aes/AES-128-CTR-decrypt (:decryption-key channel) (bu/right-zero-padded seq 16)
                                               inner)]
        [channel decrypted]))))

(deftype cs1a [keypair]
  CipherSet
  (cipher-set-id [_] "1a")
  (cipher-set-key [_] (ec/public-key keypair))
  (cipher-set-secret [_] (ec/private-key keypair))
  (create-exchange [this remote-id]
    (e3x/->E3X this (create-exchange* keypair remote-id) nil))
  (encrypt-message [_ session mbuf]
    (encrypt-message* keypair session mbuf))
  (decrypt-message [_ session mbuf]
    [session (decrypt-message* keypair mbuf)])
  (verify-message [_ session mbuf]
    (verify-message* keypair session mbuf))
  (create-channel [_ session mbuf]
    (create-channel* session mbuf))
  (encrypt-channel-message [_ channel mbuf]
    (encrypt-channel-message* channel mbuf))
  (decrypt-channel-message [_ channel mbuf]
    (decrypt-channel-message* channel mbuf)))

(defn generate []
  (let [secp160r1 (ec/generate-secp160r1)]
    (->cs1a secp160r1)))

(defn load [private public]
  (let [secp160r1 (ec/load-secp160r1 private public)]
    (->cs1a secp160r1)))
