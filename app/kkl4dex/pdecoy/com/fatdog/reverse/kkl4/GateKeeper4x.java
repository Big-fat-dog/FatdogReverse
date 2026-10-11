package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 明文诱饵（不进业务链，形似而质空）。
 *
 * 一个同名同形的假入口，fetch 恒返回空串——抓到它就收工的人，
 * 永远取不回一页数。
 */
public final class GateKeeper4x {
    private GateKeeper4x() {}

    public static String magic() {
        return "dream";
    }

    /** 假入口：恒空。 */
    public static String fetch(int page, long ts) {
        return "";
    }
}
