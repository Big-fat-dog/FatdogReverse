package com.fatdog.reverse;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Frida 关卡 5 的工具类之二：第二层 AES 解密 + 异或收尾，密钥 B 藏在 Mux。
// 同样用 NoPadding：目标明文正好 16 字节（"GRANTED_2026_OK!"），异或后整体比对。
// 真实写法：密钥和异或键作为实例字段，单例模式。
public class Mux {
    private final byte[] keyB = "PIVOT_KEY_B_0001".getBytes();
    private final int xorKey = 0x5A;

    private static volatile Mux INSTANCE;

    private Mux() {}

    public static Mux getInstance() {
        if (INSTANCE == null) {
            synchronized (Mux.class) {
                if (INSTANCE == null) INSTANCE = new Mux();
            }
        }
        return INSTANCE;
    }

    /** 实例方法：第二层解密 + 异或，返回最终明文。 */
    public String finish(byte[] in) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyB, "AES"));
        byte[] mid = c.doFinal(in);
        byte[] out = new byte[mid.length];
        for (int i = 0; i < mid.length; i++) {
            out[i] = (byte) (mid[i] ^ xorKey);
        }
        return new String(out, "UTF-8");
    }
}