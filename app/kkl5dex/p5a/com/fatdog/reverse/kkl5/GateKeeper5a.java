package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5a —— 身份与片序。
 * 只认身份：dump 出来后用于确认命中的是业务真身而非外壳。
 */
public final class GateKeeper5a {

    private GateKeeper5a() {}

    /** dump 后确认身份用的标记串。 */
    public static String magic() {
        return "ZhuXianTai:GateKeeper5";
    }

    /** 片序（第 1 片）。 */
    public static int order() {
        return 1;
    }
}
