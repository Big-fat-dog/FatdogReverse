package com.fatdog.reverse.shelly;

/**
 * 诛仙台 · 外层壳 y.* —— 回填（Wick，入口类，R8 keep）。
 * 外层壳的入口：串联 Sill/Rivet/Loom 校验后，返回下一层（壳 A）的入口类。
 * 靠 .class 常量串联下一层，R8 改名后仍自洽。
 */
public final class Wick {

    private Wick() {}

    /** 下一层入口：壳 DEX A（shellx）的 Wick。 */
    public static Class<?> nextClass() {
        return com.fatdog.reverse.shellx.Wick.class;
    }

    /** 外层职责核对：入料 + 层号 + 调度三样齐全才放行。 */
    public static boolean sane(byte[] probe) {
        if (!Sill.feed(probe)) return false;
        if (Rivet.layer() != 1) return false;
        if (Loom.route() != 2) return false;
        return true;
    }
}
