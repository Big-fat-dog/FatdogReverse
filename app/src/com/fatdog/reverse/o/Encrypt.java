package com.fatdog.reverse.o;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// 关卡 19 加密原语。注意：本包会被 R8 混淆（类名/方法名变成 a/b/c），
// 字符串也做了加密（所有算法名/路径/密钥以异或字节数组藏在 Keys 里，运行时解密）。
// 这是教程 19 第 8 节"字符串加密" + R8 混淆的真实组合。
public class Encrypt {
    static String decodeStr(int[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ 0x33);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    static byte[] decodeBytes(int[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ 0x5A);
        }
        return out;
    }

    static String aesEncode(String plain, byte[] key) {
        try {
            Cipher c = Cipher.getInstance(Keys.algAes());
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return hex(c.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "";
        }
    }

    static String aesDecode(String hex, byte[] key) {
        try {
            Cipher c = Cipher.getInstance(Keys.algAes());
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
            return new String(c.doFinal(unhex(hex)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    static String hmacSign(String msg, byte[] key) {
        try {
            Mac m = Mac.getInstance(Keys.algHmac());
            m.init(new SecretKeySpec(key, Keys.algHmac()));
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