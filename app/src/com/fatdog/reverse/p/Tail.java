package com.fatdog.reverse.p;

// 关卡 27 素材库（后半）：三把密钥的后缀段（^0x3C）。
// aeskey27 / fin_hmac / rspkey27 —— 各自与 Mk.pre() 拼成完整密钥，跨类运行时组装。
public class Tail {
    static final int[] T_REQ = {93, 89, 79, 87, 89, 69, 14, 11};
    static final int[] T_HMAC = {90, 85, 82, 99, 84, 81, 93, 95};
    static final int[] T_RSP = {78, 79, 76, 87, 89, 69, 14, 11};

    static byte[] aesReqKey() {
        return join(Mk.pre(), Cpt.decodeBytes(T_REQ, 0x3C));
    }

    static byte[] hmacKey() {
        return join(Mk.pre(), Cpt.decodeBytes(T_HMAC, 0x3C));
    }

    static byte[] aesRspKey() {
        return join(Mk.pre(), Cpt.decodeBytes(T_RSP, 0x3C));
    }

    private static byte[] join(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
