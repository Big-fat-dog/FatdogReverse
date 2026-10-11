package com.fatdog.reverse.m;

import java.lang.reflect.Method;

/**
 * L49 的诱饵：形状与 Warden 一模一样（同样的字段、私有构造函数、反射调私有解密），
 * 但密文是错的 —— 解出来是 "2OZ6" / "Gxtdog_forest_" 这种一眼像又不对的东西。
 *
 * 本类不被任何地方引用；R8 关了 shrink，所以它照旧留在 dex 里，
 * 玩家得自己判断到底哪一个才被 Bk49 递给了 native。
 */
public final class Veil {

    private final int[] m;

    private final int[] h;

    private final int s;

    private Veil(int salt) {
        this.s = salt;
        this.m = new int[] { 0x2C61, 0x2C89, 0x2CCB, 0x2CDC };
        this.h = new int[] {
            0x2CDC, 0x2C82, 0x2CC2, 0x2C89, 0x2D20, 0x2CBB, 0x2D05,
            0x2CB3, 0x2D4C, 0x2CD4, 0x2D0B, 0x2CD4, 0x2D8F, 0x2CEB
        };
    }

    public String mistTail(int mask) {
        try {
            Method md = Veil.class.getDeclaredMethod("d", int[].class, int.class);
            md.setAccessible(true);
            int[] o = (int[]) md.invoke(this, m, mask);
            StringBuilder sb = new StringBuilder(o.length);
            for (int v : o) sb.append((char) v);
            return sb.toString();
        } catch (Throwable t) {
            return "ERR_JAVA";
        }
    }

    public int[] forestHead(int mask) {
        try {
            Method md = Veil.class.getDeclaredMethod("d", int[].class, int.class);
            md.setAccessible(true);
            return (int[]) md.invoke(this, h, mask);
        } catch (Throwable t) {
            return new int[0];
        }
    }

    private int[] d(int[] c, int mask) {
        int[] o = new int[c.length];
        for (int i = 0; i < c.length; i++) {
            int b = (mask >>> ((i % 4) * 8)) & 0xFF;
            int t = (c[i] - s - i * 11) & 0xFFFF;
            o[i] = t ^ b;
        }
        return o;
    }
}
