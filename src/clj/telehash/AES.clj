(ns telehash.AES
  (:require [telehash.byte-utils :as bu])
  (:import [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec IvParameterSpec]))

(defn AES-128-CTR-encrypt [keybuf ivbuf bytes-or-seq]
  (let [cipher (Cipher/getInstance "AES/CTR/NoPadding")
        key (SecretKeySpec. (bu/ensure-byte-array keybuf) "AES")
        iv (IvParameterSpec. (bu/ensure-byte-array ivbuf))]
    (.init cipher Cipher/ENCRYPT_MODE key iv)
    (.doFinal cipher (bu/ensure-byte-array bytes-or-seq))))

(defn AES-128-CTR-decrypt [keybuf ivbuf bytes-or-seq]
  (let [cipher (Cipher/getInstance "AES/CTR/NoPadding")
        key (SecretKeySpec. (bu/ensure-byte-array keybuf) "AES")
        iv (IvParameterSpec. (bu/ensure-byte-array ivbuf))]
    (.init cipher Cipher/DECRYPT_MODE key iv)
    (.doFinal cipher (bu/ensure-byte-array bytes-or-seq))))
