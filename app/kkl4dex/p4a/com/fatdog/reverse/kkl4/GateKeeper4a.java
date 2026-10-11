package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 第一片：身份。
 *
 * 只认得自己是谁，别的什么都不管。整座塔的钥匙不在这里，
 * 这里只留一句能对上号的话。
 */
public final class GateKeeper4a {
    private GateKeeper4a() {}

    /** 身份：返回一句话，玩家 dump 出本片即见。 */
    public static String magic() {
        return "dread";
    }

    /** 片序号（本片恒为 0）。 */
    public static int slot() {
        return 0;
    }
}
