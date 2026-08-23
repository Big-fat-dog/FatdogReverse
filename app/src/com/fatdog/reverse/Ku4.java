package com.fatdog.reverse;

// 昆仑 KL4 桥：nativeProbe() 会检查运行环境是否被模拟/调试。
// 在真机上环境天然干净；在 unidbg 里需要 IOResolver 喂假文件过检。
public class Ku4 {
    static { System.loadLibrary("kunlun4"); }
    private Ku4() {}
    public static native String nativeProbe();
}
