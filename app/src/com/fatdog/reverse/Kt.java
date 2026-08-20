package com.fatdog.reverse;

// 关卡 17 的密钥碎片仓库：SM4 两把密钥 + SM3 盐 + 固定参数 dog 的前半段。
// 每段都是 XOR 字节数组，单独看数字什么也看不出；与 Fl 的后半段拼起来才是完整的。
public class Kt {
    static final byte[] RA = {90, 93, 72, 88, 89, 81, 83, 99, 90, 83, 78, 81, 99};     // ^0x3C -> fatdemo_form_
    static final byte[] RB = {55, 48, 37, 53, 52, 60, 62, 14, 35, 52, 34, 33, 14};     // ^0x51 -> fatdemo_resp_
    static final byte[] SC = {13, 10, 31, 15, 14, 6, 4, 52, 24, 6, 88, 52};            // ^0x6B -> fatdemo_sm3_
    static final byte[] DA = {27, 28, 9};                                              // ^0x7D -> fat

    static String reqPrefix() {
        return decode(RA, 0x3C);
    }

    static String rspPrefix() {
        return decode(RB, 0x51);
    }

    static String saltPrefix() {
        return decode(SC, 0x6B);
    }

    static String dogA() {
        return decode(DA, 0x7D);
    }

    private static String decode(byte[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return new String(out);
    }
}