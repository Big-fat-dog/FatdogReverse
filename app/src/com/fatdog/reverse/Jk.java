package com.fatdog.reverse;

// 关卡 16 的密钥碎片仓库：三串"废字节"分别是
// 请求密钥 / 响应密钥 / 签名盐 的前半段。
// 每段都要先异或自己的常量再转字符串；单独看数字什么也看不出。
public class Jk {
    static final byte[] RA = {60, 59, 46, 62, 63, 55, 53, 5, 40, 57, 110, 5};
    static final byte[] KA = {13, 10, 31, 15, 14, 6, 4, 52, 25, 8, 95, 52};
    static final byte[] SA = {27, 28, 9, 25, 24, 16, 18, 34, 15, 30, 73};

    static String reqPrefix() {
        return decode(RA, 0x5A);
    }

    static String rspPrefix() {
        return decode(KA, 0x6B);
    }

    static String sigPrefix() {
        return decode(SA, 0x7D);
    }

    private static String decode(byte[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return new String(out);
    }
}
