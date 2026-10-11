package com.fatdog.reverse.kkl3;

/**
 * 断魂谷 · 第五片：取数。
 *
 * 主钥派生 + 取数签名。主钥 = 遍历 16 个位置、逐位调用 3d 的混合过程，
 * 把标记码元与盐搅成 16 字节；签名则交给 native 侧（国密 + 摘要）。
 * 本片的 derive 方法体在构建期被抽走，须先回填才能算出主钥。
 */
public final class GateKeeper3 {
    private GateKeeper3() {}

    /**
     * 派生 16 字节主钥（与 gen_kkl3 纯函数逐位一致）。
     * 标记码元来自 3a，盐来自 3b，混合过程来自 3d（被抽取，须回填）。
     */
    public static byte[] derive() {
        char[] glyph = GateKeeper3a.glyph();          // 真标记码元
        byte[] brine = GateKeeper3b.brine();          // 盐
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            int mi = glyph[i % glyph.length] & 0xFF;
            int si = brine[i % brine.length] & 0xFF;
            out[i] = (byte) GateKeeper3d.mixByte(mi, si, i);
        }
        return out;
    }
}
