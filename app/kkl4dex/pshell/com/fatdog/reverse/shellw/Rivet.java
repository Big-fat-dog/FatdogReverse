package com.fatdog.reverse.shellw;

/**
 * 锁妖塔 · 多类壳（二级）· 解密 Rivet。
 *
 * 壳类群四员之二：只负责"解密"。它不持有密钥——密钥由 VM 主钥域
 * 分离派生，挂在门面 so 的 nativeFold 里，先过 VM 才有钥匙。
 * 本类只把"该交给哪一层、共几片"这件事记下来。
 */
public final class Rivet {
    private Rivet() {}

    /** 壳层序号：本类属于第 1 层（壳层）。 */
    public static int layer() {
        return 1;
    }

    /** 记录本层对应的业务片数。 */
    public static int shardCount() {
        return 9;
    }
}
