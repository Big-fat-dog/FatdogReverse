package com.fatdog.reverse.shellw;

import com.fatdog.reverse.kkl4.GateKeeper4h;

/**
 * 锁妖塔 · 多类壳（二级）· 回填 Wick（入口类，r8_shell.pro 保留原名）。
 *
 * 壳类群四员之四，也是整簇的入口：先让入料 Sill 验货、再让解密 Rivet 报层数、
 * 让调度 Loom 判齐备，最后把业务片里的 native 方法显式绑定到加载它的 ClassLoader
 * （nativeBind）。子 DexClassLoader 不会自动解析父加载器的 so，这一步是命门。
 *
 * 其余三个壳类（Sill/Rivet/Loom）与两个诱饵（Brass/Grist）都被 R8 改了名，
 * 只有本类保留——单看任何一类都拼不出这条脱壳链。
 */
public final class Wick {
    private Wick() {}

    /**
     * 回填绑定入口：先核壳类群职责，齐了才吐出要绑定的业务类。
     * 返回 null 表示链不齐（可能误入诱饵壳）。
     */
    public static Class<?> bindingClass(byte[] probe, boolean[] ready) {
        if (!Sill.feed(probe)) return null;         // 入料不过
        if (Rivet.layer() != 1) return null;        // 层号不对
        if (!Loom.route(ready)) return null;        // 片不齐
        return GateKeeper4h.class;                  // 绑定目标
    }
}
