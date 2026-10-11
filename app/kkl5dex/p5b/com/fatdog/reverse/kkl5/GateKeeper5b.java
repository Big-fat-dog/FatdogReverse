package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5b —— 页码口径。
 * 取数协议的硬常量：总页数、每页数、页码合法域。
 */
public final class GateKeeper5b {

    private GateKeeper5b() {}

    public static int pages() {
        return 100;
    }

    public static int perPage() {
        return 10;
    }

    /** 页码是否在合法域内。 */
    public static boolean pageOk(int page) {
        return page >= 1 && page <= pages();
    }
}
