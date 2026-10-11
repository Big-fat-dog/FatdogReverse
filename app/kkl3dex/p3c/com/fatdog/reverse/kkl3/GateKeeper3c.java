package com.fatdog.reverse.kkl3;

/**
 * 断魂谷 · 第三片：系数。
 *
 * 只存几个数字。单独看毫无意义，只有被 3d 的混合过程引用时才生效。
 */
public final class GateKeeper3c {
    private GateKeeper3c() {}

    /** 混合过程用的三个系数（与纯函数派生逐位一致）。 */
    public static int cA() { return 0x3D; }
    public static int cB() { return 0x29; }
    public static int cC() { return 0x1B; }
}
