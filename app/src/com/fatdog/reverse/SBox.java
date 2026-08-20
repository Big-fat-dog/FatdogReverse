package com.fatdog.reverse;

// Frida 关卡 3 的工具类：密钥 / IV / 密文都藏在这里，Activity 只负责调用。
public class SBox {
    static final byte[] KEY = "FATDEMO_KEY_12AB".getBytes();
    static final byte[] IV = "0001020304050607".getBytes();
    static final String VAULT = "Grg3J5v8Lh0r9KyE0Py0zw==";

    static String decryptVault() throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(javax.crypto.Cipher.DECRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(KEY, "AES"),
                new javax.crypto.spec.IvParameterSpec(IV));
        byte[] raw = android.util.Base64.decode(VAULT, android.util.Base64.DEFAULT);
        return new String(c.doFinal(raw), "UTF-8");
    }
}