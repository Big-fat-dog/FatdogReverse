package com.fatdog.reverse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// 关卡 26 的素材类：HMAC 密钥前半段 + 客户端证书（PKCS12）密码的前半段。
// 全部以异或字节数组保存，运行时才还原；完整的密钥/密码要和 Vd/Mc 里各自的后半段拼出来。
public class Zt {
    // HMAC 密钥前半段 "fatdemo_"（^0x3C）
    static final int[] PA = {90, 93, 72, 88, 89, 81, 83, 99};

    // PKCS12 密码前半段 "fatdemo_"（^0x37）
    static final int[] PXA = {81, 86, 67, 83, 82, 90, 88, 104};

    static String decode(int[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return new String(out);
    }

    static String pa() {
        return decode(PA, 0x3C);
    }

    static String pxa() {
        return decode(PXA, 0x37);
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
