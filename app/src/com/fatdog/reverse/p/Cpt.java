package com.fatdog.reverse.p;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// 关卡 27 加密原语。本包会被 R8 混淆（类名/方法名全部改名），
// 算法名等字符串也以异或数组藏在 Mk 里运行时还原——混淆 + 字符串加密 + 密钥拆段三件套齐上。
public class Cpt {
    static String decodeStr(int[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    static byte[] decodeBytes(int[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return out;
    }

    static String aesEncode(String plain, byte[] key) {
        try {
            Cipher c = Cipher.getInstance(Mk.algAes());
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return hex(c.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "";
        }
    }

    static String aesDecode(String hex, byte[] key) {
        try {
            Cipher c = Cipher.getInstance(Mk.algAes());
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
            return new String(c.doFinal(unhex(hex)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    static String hmacSign(String msg, byte[] key) {
        try {
            Mac m = Mac.getInstance(Mk.algHmac());
            m.init(new SecretKeySpec(key, Mk.algHmac()));
            return hex(m.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "";
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) {
            sb.append(String.format("%02x", v & 0xff));
        }
        return sb.toString();
    }

    private static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
