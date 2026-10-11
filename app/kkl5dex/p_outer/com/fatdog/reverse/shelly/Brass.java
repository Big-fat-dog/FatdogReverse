package com.fatdog.reverse.shelly;

/**
 * 诛仙台 · 外层壳 y.* —— 诱饵（Brass）。
 * 同名同形的假入口：nextClass 返回 null，走错即 NPE / ClassNotFound。
 */
public final class Brass {

    private Brass() {}

    public static Class<?> nextClass() {
        return null;
    }
}
