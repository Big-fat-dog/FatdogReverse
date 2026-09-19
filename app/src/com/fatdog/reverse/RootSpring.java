package com.fatdog.reverse;

// 天地秘境·九幽 KL50「枯木逢春」JNI 桥：libdew.so 综合收官卷。
// nativeDetect()：检测阶段（静默投毒——返回看似干净的 0，真实结果藏内部）。
// nativeVerify()：提交复测阶段（返回真实位图，露馅）。
// nativeIsTampered(bitmap)：评分阈值判定（命中 ≥3 才判环境异常）。
public class RootSpring {
    static {
        System.loadLibrary("dew");
    }

    private RootSpring() {
    }

    // 检测阶段：静默投毒，返回 0（看似干净）。
    public static native int nativeDetect();

    // 提交复测阶段：返回真实位图（bit0..bit7）。
    public static native int nativeVerify();

    // 评分阈值判定：命中数 ≥ 阈值 → 1（检测到环境异常），否则 0。
    public static native int nativeIsTampered(int bitmap);
}
