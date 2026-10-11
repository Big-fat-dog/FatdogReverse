package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5f —— 求和形态校验。
 * 总和的合法性判定（非负、在合法量级内）。
 */
public final class GateKeeper5f {

    private GateKeeper5f() {}

    public static boolean sumPlausible(long total) {
        return total >= 0L && total <= 200000L;
    }

    public static String sumText(long total) {
        return String.valueOf(total);
    }
}
