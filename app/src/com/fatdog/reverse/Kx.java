package com.fatdog.reverse;

// Frida 关卡 6 的密钥碎片一：这一半密钥以异或字节数组藏着。
// 看起来像杂项工具，实际上是 Sg 拼密钥时的左半部分。
public class Kx {
    static final byte[] PA = {90, 93, 72, 88, 89, 81, 83, 99};

    static String decodePartA() {
        byte[] out = new byte[PA.length];
        for (int i = 0; i < PA.length; i++) {
            out[i] = (byte) (PA[i] ^ 0x3C);
        }
        return new String(out);
    }
}