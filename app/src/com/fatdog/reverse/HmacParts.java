package com.fatdog.reverse;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// 关卡 11 的 HMAC 素材：签名密钥和待验明文都按字节分片异或存放。
// Activity 只持有分片还原逻辑，不再把密钥/明文直接写成一整串可读常量。
public class HmacParts {
    // key = "fatdemo_" + "hmac_key"，各段 ^0x3C
    static final int[] KA = {90, 93, 72, 88, 89, 81, 83, 99};
    static final int[] KB = {84, 81, 93, 95, 99, 87, 89, 69};
    // 待验明文 = "fat" + "lab"，各段分别 ^0x33 / ^0x5A
    private static final int[] MA = {85, 82, 71};
    private static final int[] MB = {54, 59, 56};

    private HmacParts() {}

    /** 还原完整 HMAC 密钥；Frida 可调用此方法观察结果。 */
    public static String hmacKey() {
        return dec(KA, 0x3C) + dec(KB, 0x3C);
    }

    /** 还原待验明文（正确口令）；Frida 可调用此方法观察结果。 */
    public static String passPhrase() {
        return dec(MA, 0x33) + dec(MB, 0x5A);
    }

    /** HMAC-SHA256(hmacKey, passPhrase) 指纹。 */
    public static String fingerprint() {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] d = mac.doFinal(passPhrase().getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String dec(int[] a, int key) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ key);
        }
        return new String(out, StandardCharsets.UTF_8);
    }
}
