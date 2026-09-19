package com.fatdog.reverse;

// 天地秘境·九幽 KL49「盘根错节」JNI 桥：libivy.so 新一代 root（KernelSU/APatch）检测 + Play Integrity 本地仿真。
// nativeFullCheck()：跑六类信号（内核版本串/ksu目录/环境变量/挂载点/仿PI token/Magisk兜底），返回命中位图。
// nativeIsTampered(bitmap)：评分阈值判定（命中 ≥2 才判环境异常）。
public class KernelGuard {
    static {
        System.loadLibrary("ivy");
    }

    private KernelGuard() {
    }

    // 跑六类检测信号，返回命中位图（bit0..bit5）。
    public static native int nativeFullCheck();

    // 评分阈值判定：命中数 ≥ 阈值 → 1（检测到环境异常），否则 0。
    public static native int nativeIsTampered(int bitmap);
}
