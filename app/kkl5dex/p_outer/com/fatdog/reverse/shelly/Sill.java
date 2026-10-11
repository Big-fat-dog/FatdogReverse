package com.fatdog.reverse.shelly;

/**
 * 诛仙台 · 外层壳 y.* —— 入料（Sill）。
 * 三级壳中壳的最外层：只做一件事，读入密文字节并校验魔数是否可辨。
 */
public final class Sill {

    private Sill() {}

    /** 入料校验：解封后的字节是否像 dex（魔数开头）。 */
    public static boolean feed(byte[] data) {
        if (data == null || data.length < 8) return false;
        return data[0] == 'd' && data[1] == 'e' && data[2] == 'x' && data[3] == '\n';
    }
}
