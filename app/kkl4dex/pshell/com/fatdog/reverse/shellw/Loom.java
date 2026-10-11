package com.fatdog.reverse.shellw;

/**
 * 锁妖塔 · 多类壳（二级）· 调度 Loom。
 *
 * 壳类群四员之三：只负责"调度"——判定业务片是否按数齐备。
 * 它不碰字节、不碰密钥，只看布尔位。
 */
public final class Loom {
    private Loom() {}

    /** 判定：业务片是否按 Rivet 报的片数齐备。 */
    public static boolean route(boolean[] ready) {
        if (ready == null || ready.length != Rivet.shardCount()) return false;
        for (boolean r : ready) {
            if (!r) return false;
        }
        return true;
    }
}
