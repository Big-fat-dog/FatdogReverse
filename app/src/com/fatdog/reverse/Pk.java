package com.fatdog.reverse;

import java.math.BigInteger;

// 关卡 18 的密钥仓库：RSA-1024 公钥模数（128 字节）以异或字节数组藏在这里，
// DES 密钥的一半（"key!"）也在这，另一半由服务端 /api/dskey 下发。
// 单独看数字什么也看不出，要异或 0x5A / 0x3C 还原。
public class Pk {
    // RSA 模数 n 的字节（^0x5A）
    static final int[] NX = {
            247, 160, 141, 116, 136, 238, 2, 30, 241, 117, 208, 27, 154, 12,
            217, 54, 2, 24, 209, 108, 41, 128, 24, 103, 197, 69, 222, 127,
            139, 180, 211, 4, 248, 53, 43, 146, 82, 233, 213, 33, 210, 99,
            163, 146, 246, 184, 222, 34, 177, 117, 222, 238, 79, 201, 84, 74,
            225, 105, 202, 121, 130, 100, 189, 150, 196, 1, 211, 230, 229, 205,
            168, 235, 7, 40, 253, 72, 40, 36, 137, 23, 43, 136, 103, 34,
            97, 110, 244, 169, 230, 47, 163, 149, 4, 68, 248, 155, 129, 95,
            29, 131, 233, 109, 96, 47, 184, 75, 54, 75, 246, 156, 137, 171,
            36, 4, 33, 183, 150, 239, 27, 10, 35, 46, 96, 180, 27, 38,
            117, 23,
    };
    // DES 密钥后半段 "key!"（^0x3C）
    static final byte[] HB = {87, 89, 69, 29};

    static BigInteger modulus() {
        byte[] raw = new byte[NX.length];
        for (int i = 0; i < NX.length; i++) {
            raw[i] = (byte) (NX[i] ^ 0x5A);
        }
        return new BigInteger(1, raw);
    }

    static BigInteger exp() {
        return BigInteger.valueOf((1 << 16) | 1);     // 0x10001 = 65537
    }

    static byte[] desHalfB() {
        byte[] out = new byte[HB.length];
        for (int i = 0; i < HB.length; i++) {
            out[i] = (byte) (HB[i] ^ 0x3C);
        }
        return out;
    }
}
