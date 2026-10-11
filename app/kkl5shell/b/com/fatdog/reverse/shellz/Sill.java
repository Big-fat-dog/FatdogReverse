package com.fatdog.reverse.shellz;

/**
 * 诛仙台 · 壳 DEX B —— 入料（Sill）。
 * 最内层壳：校验业务片（GateKeeper5l 所在 DEX）的字节。
 */
public final class Sill {

    private Sill() {}

    public static boolean feed(byte[] data) {
        if (data == null || data.length < 8) return false;
        return data[0] == 'd' && data[1] == 'e' && data[2] == 'x' && data[3] == '\n';
    }
}
