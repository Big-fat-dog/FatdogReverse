package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 第二片：页码。
 *
 * 只管一件事：确认要翻到第几页、每页几个数。
 * 页数不对，后面全白搭。
 */
public final class GateKeeper4b {
    private GateKeeper4b() {}

    /** 总页数。 */
    public static int pages() {
        return 100;
    }

    /** 每页个数。 */
    public static int perPage() {
        return 10;
    }

    /** 页码合法性：1..pages。 */
    public static boolean pageOk(int page) {
        return page >= 1 && page <= pages();
    }
}
