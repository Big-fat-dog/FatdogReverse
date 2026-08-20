package com.fatdog.reverse;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Frida 关卡 5 的工具类之一：第一层 AES 解密在这里，密钥 A 藏在 XBox。
// 注意用 NoPadding：这一层解密出来的还是"下一层的密文"，不能触发 PKCS5 去填充。
public class XBox {
    static final byte[] KEY_A = "PIVOT_KEY_A_0001".getBytes();

    static byte[] decryptA(String b64) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY_A, "AES"));
        byte[] raw = android.util.Base64.decode(b64, android.util.Base64.DEFAULT);
        return c.doFinal(raw);
    }
}