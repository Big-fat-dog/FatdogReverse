package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 第五片：翻页。
 *
 * 只算下一页、上一页该去哪，别的不管。
 * 依赖第二片的页码范围。
 */
public final class GateKeeper4e {
    private GateKeeper4e() {}

    /** 下一页（到头则停在最后）。 */
    public static int next(int page) {
        int last = GateKeeper4b.pages();
        return page >= last ? last : page + 1;
    }

    /** 上一页（到顶则停在第一）。 */
    public static int prev(int page) {
        return page <= 1 ? 1 : page - 1;
    }
}
