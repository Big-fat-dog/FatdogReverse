package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5d —— 增量累加器。
 * 把一页 10 个数累加进长整型，跨页推进求和。
 */
public final class GateKeeper5d {

    private GateKeeper5d() {}

    /** 单页求和。 */
    public static long sumPage(int[] nums) {
        long s = 0L;
        for (int n : nums) s += n;
        return s;
    }

    /** 跨页累加。 */
    public static long accumulate(long total, int[] nums) {
        return total + sumPage(nums);
    }
}
