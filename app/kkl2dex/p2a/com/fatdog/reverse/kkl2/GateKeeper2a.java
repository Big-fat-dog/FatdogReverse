package com.fatdog.reverse.kkl2;

/**
 * 万剑冢 · 业务第一片（身份）。独立编译成单独一个 dex，构建期用 AES-128-CBC
 * 整体加密后埋进 assets，运行时内存加载、不落盘。
 *
 * 本片只负责「身份」：给加载方一个可辨识的 magic 串，证明这一片确实被解出来了。
 * 取数签名在另一片，形状校验又在另一片——单独 dump 任何一片都拼不出完整逻辑。
 */
public final class GateKeeper2a {

    /** dump 后快速确认身份用的标记串 */
    public static String magic() {
        return "WanJianZang:GateKeeper2a";
    }

    /** 片号水印，便于玩家在 jadx 里对位「这是第几片」。 */
    public static String shard() {
        return "a";
    }
}
