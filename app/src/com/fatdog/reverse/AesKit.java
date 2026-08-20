package com.fatdog.reverse;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// 诱饵工具类：有一套完整的 AES 加解密，密钥是假的，没人调用它。
public class AesKit {
    static final byte[] FAKE_KEY = "DEADBEEF_FAKE_00".getBytes();

    static byte[] encrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(FAKE_KEY, "AES"));
        return c.doFinal(data);
    }

    static byte[] decrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(FAKE_KEY, "AES"));
        return c.doFinal(data);
    }
}