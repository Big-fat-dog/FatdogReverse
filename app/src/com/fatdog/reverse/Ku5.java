package com.fatdog.reverse;

// 昆仑 KL5 登顶：门面 so spire 经 dlsym 串起五枚内核（quarry/ridge/shard/talus/verge）。
// 与 KL3（单链接力）/ KL4（菱形分叉）的本质区别：**内核执行次序不是写死的**——
// 门面把下面五类回调揉成 s0，现算一个 5 元置换，再用「平坦化调度器」按置换派发。
// 静态读不到次序，需 trace（Frida Stalker / unidbg trace）或补全环境后直接跑出返回值。
//
// 五类回调（比 KL4 多一类，且含 64 位与静态 String 字段）：
//   climbSeed()  int                → 种子
//   baseMark()   String             → 掩码分量①
//   SUMMIT_TAG   静态 String 字段    → 掩码分量②（字段读取，非方法调用）
//   peakStamp()  long               → 掩码分量③
//   routePlan()  int[]（6 段）       → 前五段喂内核，第六段掺掩码
public class Ku5 {
    static {
        System.loadLibrary("quarry");
        System.loadLibrary("ridge");
        System.loadLibrary("shard");
        System.loadLibrary("talus");
        System.loadLibrary("verge");
        System.loadLibrary("spire");
    }

    private Ku5() {}

    public static native String nativeClimb();

    // 完整校验在 so 内完成：环境干净且令牌正确才返回 1。
    public static native int nativeSubmit(String token);

    // ① int 回调：种子
    public static int climbSeed() {
        return 0x20260505;
    }

    // ② String 回调：掩码分量①
    public static String baseMark() {
        int[] pa = {0x46, 0x61, 0x74, 0x64, 0x6f, 0x67, 0x5f};
        StringBuilder sb = new StringBuilder(pa.length);
        for (int v : pa) sb.append((char) v);
        return sb.toString();
    }

    // ③ 静态 String 字段：掩码分量②（以字段形式读取，非方法调用）
    public static String SUMMIT_TAG = "kunlun_ridge";

    // ④ long 回调：掩码分量③（64 位）
    public static long peakStamp() {
        return 0x12345678ABCDEF01L;
    }

    // ⑤ int[] 回调：六段盐（前五段喂内核，第六段掺掩码）
    public static int[] routePlan() {
        return new int[]{0x11223344, 0x23344556, 0x34455667, 0x45566778, 0x56677889, 0x6778899A};
    }

    // 诱饵：一字之差的备用标记 / 空盐 / 备用种子，无人调用
    public static String ridgeTag() {
        int[] pa = {0x6b, 0x75, 0x6e, 0x6c, 0x75, 0x6e, 0x5f, 0x72, 0x69, 0x64, 0x67, 0x65, 0x73};
        StringBuilder sb = new StringBuilder(pa.length);
        for (int v : pa) sb.append((char) v);
        return sb.toString();
    }

    public static String SUMMIT_TAG_ALT = "kunlun_ridges";

    public static int spareSeed() { return 0; }

    public static int[] spareRoute() { return new int[]{0, 0, 0, 0, 0, 0}; }
}
