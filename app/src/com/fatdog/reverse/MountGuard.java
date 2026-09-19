package com.fatdog.reverse;

// 天地秘境·九幽 KL48「斩草除根」JNI 桥：libyew.so 挂载点 / mount namespace 深检 + magiskd 进程检测。
// nativeFullCheck()：跑七类信号（mountinfo tmpfs 覆盖 / magisk 挂载点 / dex2oat loop / magiskd 进程 / mounts / 环境变量 / native bridge），返回命中位图。
// nativeIsTampered(bitmap)：评分阈值判定（命中 ≥2 才判环境异常）。
public class MountGuard {
    static {
        System.loadLibrary("yew");
    }

    private MountGuard() {
    }

    // 跑七类检测信号，返回命中位图（bit0..bit6）。
    public static native int nativeFullCheck();

    // 评分阈值判定：命中数 ≥ 阈值 → 1（检测到环境异常），否则 0。
    public static native int nativeIsTampered(int bitmap);
}
