package com.fatdog.reverse.shelly;

/**
 * 诛仙台 · 外层壳 y.* —— 解密（Rivet）。
 * 记录当前层号；逐层解密的真正密钥在 native 里由 VM 主钥域派生。
 */
public final class Rivet {

    private Rivet() {}

    /** 当前层号（外层 = 1）。 */
    public static int layer() {
        return 1;
    }
}
