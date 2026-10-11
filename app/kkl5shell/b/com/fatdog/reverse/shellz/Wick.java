package com.fatdog.reverse.shellz;

/**
 * 诛仙台 · 壳 DEX B —— 回填（Wick，入口类，R8 keep）。
 * 最内层壳入口：串联 Sill/Rivet/Loom 后返回业务片的 native 绑定目标类。
 * bindingClass 是门面 nativeBind 的目标——业务片 GateKeeper5l.nativeSign 靠它显式绑定。
 */
public final class Wick {

    private Wick() {}

    public static Class<?> bindingClass() {
        return com.fatdog.reverse.kkl5.GateKeeper5l.class;
    }

    public static boolean sane(byte[] probe) {
        if (!Sill.feed(probe)) return false;
        if (Rivet.layer() != 3) return false;
        if (Loom.route() != 4) return false;
        return true;
    }
}
