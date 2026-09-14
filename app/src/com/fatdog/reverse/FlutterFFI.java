package com.fatdog.reverse;

/**
 * KL39 月下独酌（碧落天 · Dart FFI 双向往调）
 * JNI 桥类：模拟 Dart FFI 边界——Dart 调用 native 加密，native 回调 Dart 获取密钥碎片
 *
 * 动态注册（JNI_OnLoad RegisterNatives）：
 *   nativeEncRequest / nativeDeriveKey / nativeSign / nativeVerify / nativeAnswer / nativeGetStatus
 *
 * 考点：
 *   1. Dart FFI 双向往调——Dart→C 加密，C→Dart 取密钥碎片
 *   2. 密钥分两侧各存一半，运行时拼装
 *   3. FFI 函数注册表（DartNativeFunction 数组）
 *   4. 反调试检测 + 静默投毒
 *
 * 反逆向对抗：
 *   - ptrace/TracerPid 检测调试附加
 *   - /proc/self/maps 扫描 Frida 特征
 *   - 27042-27044 端口探测
 *   - 线程名扫描
 *   - 检测命中即静默投毒密钥一字节
 *
 * 标记：Fatdog_moon（真）/ Fatdog_star（诱饵）
 */
public class FlutterFFI {
    static {
        System.loadLibrary("bow");
    }

    private FlutterFFI() {}

    // ==================== 动态注册方法（JNI_OnLoad RegisterNatives） ====================

    /**
     * 构建 FFI 加密的请求参数（模拟 Dart→C FFI 调用链加密）
     * @param page 页码
     * @param ts   时间戳
     * @return XOR 加密后的请求参数字节数组
     */
    public static native byte[] nativeEncRequest(int page, long ts);

    /**
     * 从 Dart 侧取回完整密钥（模拟 C→Dart 回调获取密钥碎片并拼装）
     * 调用前会执行反调试检测，检测到逆向即投毒
     *
     * @return 拼装后的完整密钥 hex 字符串（检测触发时返回 "guard_failed"）
     */
    public static native String nativeDeriveKey();

    /**
     * 计算 HMAC-SHA256 签名
     * 调用前会执行反调试检测，检测到逆向即投毒
     *
     * @param page 页码
     * @param ts   时间戳
     * @return 签名字符串（检测触发时返回 "guard_failed"）
     */
    public static native String nativeSign(int page, long ts);

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
     * 返回反调试自检状态 + FFI 注册表信息（调试/教学用）
     * @return 状态字符串
     */
    public static native String nativeGetStatus();
}
