package com.fatdog.reverse;

// 天地秘境·九幽 KL46「落叶归根」JNI 桥：libelm.so 多层 Root 环境检测。
// nativeFullCheck()：跑七类环境信号，返回命中位图（bit0..bit6）。
// nativeIsRooted(bitmap)：评分阈值判定（命中 ≥3 才判 Root）。
// 破解路线：hook 属性/文件探测过滤，或 Magisk DenyList 隐藏 su/magisk，或 patch so。
public class RootSentinel {
    static {
        System.loadLibrary("elm");
    }

    private RootSentinel() {
    }

    // 跑七类检测信号，返回命中位图（bit0..bit6）。
    public static native int nativeFullCheck();

    // 评分阈值判定：命中数 ≥ 阈值 → 1（检测到 Root），否则 0。
    public static native int nativeIsRooted(int bitmap);
}
