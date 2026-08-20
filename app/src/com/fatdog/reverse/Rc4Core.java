package com.fatdog.reverse;

// RC4 流密码的教科书实现：KSA（密钥调度）把 256 字节 S 盒打乱，
// PRGA（伪随机生成）边搅 S 盒边吐密钥流，明文逐字节异或密钥流就是密文。
// 解密 = 用同一把密钥再跑一遍（异或对称）。本类只是加解密原语，被 C16 调用。
public class Rc4Core {
    static byte[] crypt(byte[] data, byte[] key) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) {
            s[i] = i;
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {          // KSA
            j = (j + s[i] + (key[i % key.length] & 0xff)) & 0xff;
            int t = s[i];
            s[i] = s[j];
            s[j] = t;
        }
        byte[] out = new byte[data.length];
        int x = 0;
        j = 0;
        for (int i = 0; i < data.length; i++) {  // PRGA
            x = (x + 1) & 0xff;
            j = (j + s[x]) & 0xff;
            int t = s[x];
            s[x] = s[j];
            s[j] = t;
            out[i] = (byte) (data[i] ^ s[(s[x] + s[j]) & 0xff]);
        }
        return out;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) {
            sb.append(String.format("%02x", v & 0xff));
        }
        return sb.toString();
    }

    static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
