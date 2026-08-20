package com.fatdog.reverse;

// 字符串异或工具：所有"文案/关键字符串"都以异或字节数组存着，运行时经它还原。
// 这样 jadx 里看到的是一堆神秘数字，而不是明文字符串（教程 19 第 8 节的做法）。
public class Sx {
    static final int K = 0x4D;

    static String s(int[] a) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ K);
        }
        return new String(out, java.nio.charset.StandardCharsets.UTF_8);
    }
}