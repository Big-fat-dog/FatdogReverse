package com.fatdog.reverse.shellw;

/**
 * 锁妖塔 · 多类壳（二级）· 诱饵 Brass。
 *
 * 与真壳类群同名同形的假壳：形状像 Wick，行为却是空的。
 * 抓到第一个壳类就收工的人，会在这里撞上"形似而质空"。
 */
public final class Brass {
    private Brass() {}

    /** 假回填：恒返回 null（真 Wick.bindingClass 返回的是真类）。 */
    public static Class<?> bindingClass(byte[] probe, boolean[] ready) {
        return null;
    }
}
