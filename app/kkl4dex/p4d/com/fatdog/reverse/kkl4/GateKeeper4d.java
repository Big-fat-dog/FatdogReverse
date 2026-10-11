package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 第四片：累加。
 *
 * 把一页一页拿回来的数攒起来，最后合成一个总数。
 * 依赖第三片的页码口径，本片只做加法。
 */
public final class GateKeeper4d {
    private GateKeeper4d() {}

    /** 增量累加：把本页 numbers 加进 running，返回新累计值。 */
    public static long accrue(long running, int[] numbers) {
        long r = running;
        if (numbers != null) {
            for (int n : numbers) r += n;
        }
        return r;
    }

    /** 从零起步。 */
    public static long start() {
        return 0L;
    }
}
