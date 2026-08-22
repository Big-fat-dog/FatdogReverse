package com.fatdog.reverse;

// 关卡 27 诱饵：名字带 End 很像核心类，实际无人调用。
// 假 HMAC 密钥、假端点——拿去复刻只会 403/签名错误。
public class EndKit {
    // ^0x3C：fatdemo_ + end_fake_ky = fatdemo_end_fake_ky（假密钥）
    static final int[] PA = {90, 93, 72, 88, 89, 81, 83, 99};
    static final int[] PB = {89, 82, 88, 99, 90, 93, 87, 89, 99, 87, 69};
    // ^0x25：/api/end（假端点）
    static final int[] PP = {10, 68, 85, 76, 10, 64, 75, 65};

    static String partA() {
        byte[] o = new byte[PA.length];
        for (int i = 0; i < PA.length; i++) o[i] = (byte) (PA[i] ^ 0x3C);
        return new String(o);
    }

    static String partB() {
        byte[] o = new byte[PB.length];
        for (int i = 0; i < PB.length; i++) o[i] = (byte) (PB[i] ^ 0x3C);
        return new String(o);
    }

    static String buildKey() {
        return partA() + partB();
    }

    static String path() {
        byte[] o = new byte[PP.length];
        for (int i = 0; i < PP.length; i++) o[i] = (byte) (PP[i] ^ 0x25);
        return new String(o);
    }
}
