package com.fatdog.reverse;

/**
 * KL37 风中鸢尾（碧落天 · Dart Kernel 字节码逆向）
 * JNI 桥类：混合注册（静态命名 + 动态 RegisterNatives）
 *
 * 静态注册：nativeGetBytecodeBlob / nativeGetAlgorithmInfo
 * 动态注册：nativeExecute / nativeVerify / nativeAnswer / nativeGetStatus
 *
 * 反逆向对抗：
 *   ① ptrace/TracerPid + maps/端口/线程名四路哨兵
 *   ② 函数头 inline hook 检测
 *   ③ .text 段 CRC 自校验
 *   ④ 检测命中即静默投毒密钥一字节，服务端 403
 *
 * 标记：Fatdog_kite（真）/ Fatdog_sail（诱饵）
 */
public class FlutterCore {
    static {
        System.loadLibrary("fluttercore");
    }

    private FlutterCore() {}

    // ==================== 静态注册方法（标准 JNI 命名） ====================

    /**
     * 获取 Dart Kernel 字节码 blob（模拟 AOT 编译产物）
     * @return 加密的字节码字节数组
     */
    public static native byte[] nativeGetBytecodeBlob();

    /**
     * 返回算法信息（教学用途）
     * @return 算法描述字符串
     */
    public static native String nativeGetAlgorithmInfo();

    // ==================== 动态注册方法（JNI_OnLoad RegisterNatives） ====================

    /**
     * 执行字节码并返回 HMAC-SHA256 签名
     * 调用前会执行四路哨兵 + CRC 自校验，检测到逆向即投毒
     *
     * @param page 页码
     * @param ts   时间戳
     * @return 签名字符串（检测触发时返回 "guard_failed"）
     */
    public static native String nativeExecute(int page, long ts);

    /**
     * 验证签名是否正确
     * @param page 页码
     * @param ts   时间戳
     * @param sign 待验证的签名
     * @return true 如果签名正确
     */
    public static native boolean nativeVerify(int page, long ts, String sign);

    /**
     * 返回答案（本地比对用）
     * @return 答案字符串（8位hex）
     */
    public static native String nativeAnswer();

    /**
     * 返回哨兵自检状态（调试/教学用）
     * @return 状态字符串
     */
    public static native String nativeGetStatus();
}
