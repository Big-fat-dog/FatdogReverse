package com.fatdog.reverse.shellw;

/**
 * 锁妖塔 · 多类壳（二级）· 入料 Sill。
 *
 * 壳类群四员之一：只负责"入料"——接住已经解开的 dex 字节，
 * 校验魔数与长度，别的什么都不做。单看这一类，拼不出整条脱壳链。
 */
public final class Sill {
    private Sill() {}

    /** 校验一段 dex 字节是否是合法 dex（魔数 + 长度门槛）。 */
    public static boolean feed(byte[] dex) {
        if (dex == null || dex.length < 8) return false;
        return dex[0] == 'd' && dex[1] == 'e' && dex[2] == 'x' && dex[3] == '\n';
    }
}
