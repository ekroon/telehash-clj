(ns telehash.cs1a
  (:refer-clojure :exclude [load])
  (:require [telehash.e3x :as e3x]
            [telehash.SHA :as sha]
            [telehash.AES :as aes]
            [telehash.elliptic-curve :as ec])
  (:import telehash.e3x.CipherSet))

(defn- create-exchange* [remote-id]
  (let [ephemeral (ec/generate-secp160r1)
        seq (rand-int Integer/MAX_VALUE)]
    {:endpoint remote-id
     :ephemeral ephemeral
     :token (-> ephemeral
                (ec/public-key) (e3x/make-n-bytes 16) (sha/bytes->SHA256) (e3x/make-n-bytes 16))
     :seq (rand-int Integer/MAX_VALUE)}))

(defn- encrypt-message* [local session msgbuf]
  "local secp"
  (let [{:keys [endpoint ephemeral seq]} session
        shared-secret (ec/calculate-shared-secret ephemeral endpoint)
        aes-key (e3x/fold (sha/bytes->SHA256 shared-secret) 1)
        new-seq (inc seq)
        iv (e3x/int->bytes new-seq)
        padded-iv (byte-array (concat iv (e3x/zeros 12)))
        encrypted (aes/AES-128-CTR-encrypt aes-key padded-iv msgbuf)
        mac-secret (ec/calculate-shared-secret local endpoint)
        macd (byte-array (concat (ec/public-key ephemeral) iv encrypted))
        hmac (e3x/fold (sha/HMAC-SHA256 (byte-array (concat mac-secret iv)) macd) 3)]
    [(assoc session :seq new-seq)
     (byte-array (concat macd hmac))]))

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

(defn- decrypt-message* [secp160r1 msgbuf]
  (if-let [message (bytes->1a-message msgbuf)]
    (let [shared-secret (ec/calculate-shared-secret secp160r1 (:key message))
          aes-key (e3x/fold (sha/bytes->SHA256 shared-secret) 1)
          padded-iv (byte-array (concat (:iv message) (e3x/zeros 12)))
          decrypted (aes/AES-128-CTR-decrypt aes-key padded-iv (:inner message))]
      decrypted)
    nil))

(deftype cs1a [keypair]
  CipherSet
  (cipher-set-id [_] "1a")
  (cipher-set-key [_] (ec/public-key keypair))
  (cipher-set-secret [_] (ec/private-key keypair))
  (create-exchange [this remote-id]
    (e3x/->E3X this (create-exchange* remote-id)))
  (encrypt-message [_ session mbuf]
    (encrypt-message* keypair session mbuf))
  (decrypt-message [_ session mbuf]
    [session (decrypt-message* keypair mbuf)]))

(defn generate []
  (let [secp160r1 (ec/generate-secp160r1)]
    (->cs1a secp160r1)))

(defn load [private public]
  (let [secp160r1 (ec/load-secp160r1 private public)]
    (->cs1a secp160r1)))
