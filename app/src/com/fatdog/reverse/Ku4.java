package com.fatdog.reverse;

// 昆仑 KL4 冰裂缝：门面 so gulch 经 dlsym 串起五枚内核（iris/juniper/kindle/larch/marrow），
// 数据流是"菱形分叉"：iris↔juniper 同源分叉，各带一枚中继（kindle/larch），最后归并到 marrow。
// nativeProbe() 先做反模拟体检，再向本类索取**四类**回调：String（headMark）、
// int（forkSeed）、静态 int 字段（SPLIT_X）、int[]（saltPlan）——比 KL3 的两类更重，
// unidbg 玩家需在 AbstractJni 子类里分别 override callStaticObjectMethod、
// callStaticIntMethod、getStaticIntField，并按数组读回调返回的 int[]。
public class Ku4 {
    static {
        System.loadLibrary("iris");
        System.loadLibrary("juniper");
        System.loadLibrary("kindle");
        System.loadLibrary("larch");
        System.loadLibrary("marrow");
        System.loadLibrary("gulch");
    }

    private Ku4() {}

    public static native String nativeProbe();

    // 完整校验在 so 内完成：环境干净且令牌正确才返回 1。
    public static native int nativeSubmit(String token);

    // ① String 回调：前段明文（"Fatdog_"）
    public static String headMark() {
        int[] pa = {0x46, 0x61, 0x74, 0x64, 0x6f, 0x67, 0x5f};
        StringBuilder sb = new StringBuilder(pa.length);
        for (int v : pa) sb.append((char) v);
        return sb.toString();
    }

    // ② int 回调：fork 状态种子
    public static int forkSeed() {
        return 0x20260404;
    }

    // ③ 静态 int 字段：分叉掩码（以字段形式读取，非方法调用）
    public static int SPLIT_X = 0x5A5A5A5A;

    // ④ int[] 回调：五段盐（顺序 = iris/juniper/kindle/larch/marrow）
    public static int[] saltPlan() {
        return new int[]{0x1F3A, 0x2E4B, 0x3D5C, 0x4C6D, 0x5B7E};
    }

    // 诱饵：一字之差的"另一半"与备用字段，无人调用
    public static String tailMark() {
        int[] pa = {0x46, 0x61, 0x74, 0x64, 0x6f, 0x67};
        StringBuilder sb = new StringBuilder(pa.length);
        for (int v : pa) sb.append((char) v);
        return sb.toString();
    }

    public static int spareSeed() { return 0; }

    public static int SPLIT_Y = 0x0;
}
