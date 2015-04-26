(ns telehash.AES
  (:import [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec IvParameterSpec]))

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
