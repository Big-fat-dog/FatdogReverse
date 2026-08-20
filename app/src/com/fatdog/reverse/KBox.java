package com.fatdog.reverse;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Frida 关卡 4 的工具类之二：令牌的 AES 解密校验在这，密钥和密文也藏在这里。
public class KBox {
    static final byte[] TOKEN_KEY = "NEON_TOKEN_KEY16".getBytes();
    static final String TOKEN_ENC = "WG2qYEkmVR5yFwooXN1VSw==";

    static boolean checkToken(String token) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(TOKEN_KEY, "AES"));
        byte[] raw = android.util.Base64.decode(TOKEN_ENC, android.util.Base64.DEFAULT);
        return new String(c.doFinal(raw), "UTF-8").equals(token);
    }
}