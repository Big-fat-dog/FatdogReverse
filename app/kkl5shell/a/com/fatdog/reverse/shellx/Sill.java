package com.fatdog.reverse.shellx;

/**
 * 诛仙台 · 壳 DEX A —— 入料（Sill）。
 * 二级壳类群：与外层同名不同实现，职责是校验内层（壳 B）的字节。
 */
public final class Sill {

    private Sill() {}

    public static boolean feed(byte[] data) {
        if (data == null || data.length < 8) return false;
        return data[0] == 'd' && data[1] == 'e' && data[2] == 'x' && data[3] == '\n';
    }
}
