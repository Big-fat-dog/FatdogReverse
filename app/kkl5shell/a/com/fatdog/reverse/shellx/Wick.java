package com.fatdog.reverse.shellx;

/**
 * 诛仙台 · 壳 DEX A —— 回填（Wick，入口类，R8 keep）。
 * 二级壳入口：串联 Sill/Rivet/Loom 后返回下一层（壳 B）的入口类。
 */
public final class Wick {

    private Wick() {}

    public static Class<?> nextClass() {
        return com.fatdog.reverse.shellz.Wick.class;
    }

    public static boolean sane(byte[] probe) {
        if (!Sill.feed(probe)) return false;
        if (Rivet.layer() != 2) return false;
        if (Loom.route() != 3) return false;
        return true;
    }
}
