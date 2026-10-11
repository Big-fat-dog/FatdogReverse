package com.fatdog.reverse.shelly;

/**
 * 诛仙台 · 外层壳 y.* —— 诱饵（Grist）。
 * 同名同形的假入口：sane 恒 false，走错即被外层拦下。
 */
public final class Grist {

    private Grist() {}

    public static Class<?> nextClass() {
        return null;
    }

    public static boolean sane(byte[] probe) {
        return false;
    }
}
