package com.fatdog.reverse;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Frida 关卡 5 的工具类之二：第二层 AES 解密 + 异或收尾，密钥 B 藏在 Mux。
// 同样用 NoPadding：目标明文正好 16 字节（"GRANTED_2026_OK!"），异或后整体比对。
public class Mux {
    static final byte[] KEY_B = "PIVOT_KEY_B_0001".getBytes();
    static final int XOR_KEY = 0x5A;

    static String finish(byte[] in) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY_B, "AES"));
        byte[] mid = c.doFinal(in);
        byte[] out = new byte[mid.length];
        for (int i = 0; i < mid.length; i++) {
            out[i] = (byte) (mid[i] ^ XOR_KEY);
        }
        return new String(out, "UTF-8");
    }
}