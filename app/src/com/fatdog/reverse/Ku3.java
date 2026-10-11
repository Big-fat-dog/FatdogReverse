package com.fatdog.reverse;

// 昆仑 KL3 桥：门面 so acorn 经 dlsym 串起五枚内核（bramble/cinder/drift/elder/fable），
// nativeKey() 先向本类索取前段（halfA）与状态初值（bridgeSeed），再沿链取尾段。
// unidbg 玩家需在 AbstractJni 子类中**同时**补 callStaticObjectMethod 与 callStaticIntMethod。
public class Ku3 {
    static {
        System.loadLibrary("bramble");
        System.loadLibrary("cinder");
        System.loadLibrary("drift");
        System.loadLibrary("elder");
        System.loadLibrary("fable");
        System.loadLibrary("acorn");
    }

    private Ku3() {}

    public static native String nativeKey();

    // 前段明文（String 回调）："Fatdog_"
    public static String halfA() {
        int[] pa = {0x46,0x61,0x74,0x64,0x6f,0x67,0x5f};
        StringBuilder sb = new StringBuilder(pa.length);
        for (int v : pa) sb.append((char) v);
        return sb.toString();
    }

    // 状态初值（int 回调）：链上五枚内核的片段选择由它播种
    public static int bridgeSeed() {
        return 0x20260303;
    }

    // 诱饵：一字之差的"另一半"，无人调用
    public static String halfB() {
        int[] pa = {0x46,0x61,0x74,0x64,0x6f,0x67};
        StringBuilder sb = new StringBuilder(pa.length);
        for (int v : pa) sb.append((char) v);
        return sb.toString();
    }
}
