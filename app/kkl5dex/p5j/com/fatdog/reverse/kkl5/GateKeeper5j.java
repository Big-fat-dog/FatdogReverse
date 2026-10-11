package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5j —— 壳层口径。
 * 三级壳中壳 + 13 业务片的层数/片数常量（教学性：让玩家看清壳的层级）。
 */
public final class GateKeeper5j {

    private GateKeeper5j() {}

    public static int shellLayers() {
        return 3;
    }

    public static int shards() {
        return 13;
    }
}
