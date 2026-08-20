package com.fatdog.reverse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// 关卡 24 密钥碎片一：HMAC 密钥的前半段 "fatdemo_"（异或数组），HMAC 计算也在这。
public class Tk {
    static final int[] PA = {90, 93, 72, 88, 89, 81, 83, 99};      // ^0x3C -> fatdemo_

    static String partA() {
        byte[] out = new byte[PA.length];
        for (int i = 0; i < PA.length; i++) {
            out[i] = (byte) (PA[i] ^ 0x3C);
        }
        return new String(out);
    }

    static String hmacSha256Hex(String key, String msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256"));
            byte[] d = mac.doFinal(msg.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
