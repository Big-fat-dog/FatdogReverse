package com.fatdog.reverse;

// 天地秘境·九幽 KL47「深根固蒂」JNI 桥：liboak.so Bootloader 解锁 + 系统属性深检。
// nativeFullCheck()：跑七类信号（verifiedbootstate/vbmeta/lockstate/cmdline/debugprops/native_bridge/自定义ROM），返回命中位图。
// nativeIsTampered(bitmap)：评分阈值判定（命中 ≥2 才判环境异常）。
public class BootGuard {
    static {
        System.loadLibrary("oak");
    }

    private BootGuard() {
    }

    // 跑七类检测信号，返回命中位图（bit0..bit6）。
    public static native int nativeFullCheck();

    // 评分阈值判定：命中数 ≥ 阈值 → 1（检测到环境异常），否则 0。
    public static native int nativeIsTampered(int bitmap);
}
