package com.fatdog.reverse.kkl3;

/**
 * 断魂谷 · 第一片：身份。
 *
 * 只认得自己是谁，别的什么都不管。真标记的码元散在这里，
 * 与别的片拼起来才成完整一句话。
 */
public final class GateKeeper3a {
    private GateKeeper3a() {}

    /** 身份：返回一句话，玩家 dump 出本片即见。 */
    public static String magic() {
        return "quell";
    }

    /** 真标记的码元（UTF-16 单元），与 3b 的盐拼起来派生出主钥。 */
    public static char[] glyph() {
        return new char[]{'F', 'a', 't', 'd', 'o', 'g', '_', 'q', 'u', 'e', 'l', 'l'};
    }
}
