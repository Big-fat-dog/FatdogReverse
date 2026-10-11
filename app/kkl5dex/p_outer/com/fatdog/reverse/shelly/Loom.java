package com.fatdog.reverse.shelly;

/**
 * 诛仙台 · 外层壳 y.* —— 调度（Loom）。
 * 判定下一层是「壳 A」还是「业务」：外层永远先指向壳 A（层 2）。
 */
public final class Loom {

    private Loom() {}

    /** 下一层目标（外层 → 壳 A = 2）。 */
    public static int route() {
        return 2;
    }
}
