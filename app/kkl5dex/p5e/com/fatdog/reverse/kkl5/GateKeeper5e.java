package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5e —— 翻页纯函数。
 * 页码推进的边界判定，依赖 5b 的页码口径。
 */
public final class GateKeeper5e {

    private GateKeeper5e() {}

    public static int next(int page) {
        return (page < GateKeeper5b.pages()) ? page + 1 : page;
    }

    public static int prev(int page) {
        return (page > 1) ? page - 1 : page;
    }
}
