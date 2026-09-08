package com.fatdog.reverse;

// 昆仑 KL4 桥：nativeProbe() 会检查运行环境是否被模拟/调试。
// 在真机上环境天然干净；在 unidbg 里需要 IOResolver 喂假文件过检。
public class Ku4 {
    static { System.loadLibrary("rivet"); }
    private Ku4() {}
    public static native String nativeProbe();

    // 完整校验在 so 内完成：环境干净且令牌正确才返回 1。
    public static native int nativeSubmit(String token);
}
