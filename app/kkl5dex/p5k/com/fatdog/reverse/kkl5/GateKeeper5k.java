package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5k —— 聚合器。
 * 依赖 5d 的增量累加，做跨页聚合的入口。
 */
public final class GateKeeper5k {

    private GateKeeper5k() {}

    public static long fold(long total, int[] nums) {
        return GateKeeper5d.accumulate(total, nums);
    }
}
