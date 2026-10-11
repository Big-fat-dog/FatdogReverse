package com.fatdog.reverse.kkl3;

/**
 * 断魂谷 · 第四片：混合。
 *
 * 把"标记码元 + 盐 + 系数"搅成单个字节的纯粹过程。
 * 本片的方法体在构建期被抽走（桩化），真实字节码躺在 dex 尾部的
 * 自定义结构里；只有首次被调用、触发了回填，它才真正能跑。
 */
public final class GateKeeper3d {
    private GateKeeper3d() {}

    /**
     * 混合一个字节（与纯函数 mix_byte 逐位一致）：
     *   mi = marker[i % len(marker)]，si = salt[i % len(salt)]
     *   x  = (mi*0x3D + si*0x29 + i*0x1B) & 0xFF
     *   x ^= (si << 2) & 0xFF
     *   x  = ror8(x, 3)
     *   x ^= mi ^ (i & 0x7F)
     */
    public static int mixByte(int mi, int si, int i) {
        int cA = GateKeeper3c.cA();   // 0x3D
        int cB = GateKeeper3c.cB();   // 0x29
        int cC = GateKeeper3c.cC();   // 0x1B
        int x = (mi * cA + si * cB + i * cC) & 0xFF;
        x ^= (si << 2) & 0xFF;
        x = ((x >> 3) | (x << 5)) & 0xFF;   // ror8 3
        x ^= mi ^ (i & 0x7F);
        return x & 0xFF;
    }
}
