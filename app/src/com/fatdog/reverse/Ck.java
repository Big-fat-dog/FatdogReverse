package com.fatdog.reverse;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Ck {
    static { System.loadLibrary("loom"); }

    public static native byte[] nativeBuildRequest(int page, long ts);
    public static native boolean nativeVerifyResponse(byte[] data);
    public static native int nativeCode(byte[] data);
    public static native int[] nativeParseNums(byte[] data);
    public static native byte[] nativeSign(byte[] data);

    private static final byte[] HMAC_KEY = "Fatdog_weave".getBytes();

    public static boolean verifySignature(byte[] data) {
        byte[] sign = nativeSign(data);
        if (sign == null || sign.length < 32) return false;
        int code = nativeCode(data);
        int[] nums = nativeParseNums(data);
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(_varint((code << 3) | 0));
            bos.write(_varint(code));
            for (int n : nums) {
                bos.write(_varint((2 << 3) | 0));
                bos.write(_varint(n & 0xffffffffL));
            }
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(HMAC_KEY, "HmacSHA256"));
            byte[] expected = mac.doFinal(bos.toByteArray());
            return MessageDigest.isEqual(expected, sign);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] _varint(long value) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        while (value > 0x7F) {
            bos.write((int)(value & 0x7F) | 0x80);
            value >>= 7;
        }
        bos.write((int)(value & 0x7F));
        return bos.toByteArray();
    }
}
