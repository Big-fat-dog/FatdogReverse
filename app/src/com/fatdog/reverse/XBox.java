package com.fatdog.reverse;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Frida 关卡 5 的工具类之一：第一层 AES 解密在这里，密钥 A 藏在 XBox。
// 注意用 NoPadding：这一层解密出来的还是"下一层的密文"，不能触发 PKCS5 去填充。
// 真实写法：密钥实例字段，Cipher 实例可缓存，单例模式。
public class XBox {
    private final byte[] keyA = "PIVOT_KEY_A_0001".getBytes();

    private static volatile XBox INSTANCE;

    private XBox() {}

    public static XBox getInstance() {
        if (INSTANCE == null) {
            synchronized (XBox.class) {
                if (INSTANCE == null) INSTANCE = new XBox();
            }
        }
        return INSTANCE;
    }

    /** 实例方法：第一层解密，返回中间字节数组。 */
    public byte[] decryptA(String b64) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyA, "AES"));
        byte[] raw = android.util.Base64.decode(b64, android.util.Base64.DEFAULT);
        return c.doFinal(raw);
    }
}