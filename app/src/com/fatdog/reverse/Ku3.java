package com.fatdog.reverse;

// 昆仑 KL3 桥：native 回调本类的 halfA() 取前半密钥，与 so 内后半拼合。
// unidbg 玩家需在 AbstractJni 子类中拦截 halfA 回调并返回正确值。
public class Ku3 {
    static { System.loadLibrary("maple"); }

    private Ku3() {}

    public static native String nativeKey();

    public static String halfA() {
        int[] pa = {0x46,0x61,0x74,0x64,0x6f,0x67,0x5f};
        StringBuilder sb = new StringBuilder(pa.length);
        for (int v : pa) sb.append((char) v);
        return sb.toString();
    }
}
