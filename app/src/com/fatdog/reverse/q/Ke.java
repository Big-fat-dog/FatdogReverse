package com.fatdog.reverse.q;

// 关卡 31：密钥前半截的藏身处。q 子包不在 r8.pro 白名单里——构建时整个类被 R8 改名，
// jadx 里别想直接搜到 com.fatdog.reverse.q.Ke；但 partA 方法名经 keepclassmembers 保留，
// 因为 libl31.so 要按这个名字回调取件。int 码点表即十六进制字面值的数组写法。
public class Ke {
    private static final int[] PA = {0x46, 0x61, 0x74, 0x64, 0x6f, 0x67, 0x5f};   // "Fatdog_"

    public static String partA() {
        StringBuilder sb = new StringBuilder(PA.length);
        for (int v : PA) sb.append((char) v);
        return sb.toString();
    }

    private Ke() {
    }
}
