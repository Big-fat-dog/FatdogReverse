package com.fatdog.reverse;

/**
 * KL38 雾里观花（碧落天 · Flutter 网络层 Hook）
 * JNI 桥类：混合注册（静态命名 + 动态 RegisterNatives）
 *
 * 静态注册：nativeBuildRequest / nativeGetPinHash
 * 动态注册：nativeSign / nativeVerify / nativeAnswer / nativeGetStatus
 *
 * 考点：
 *   1. Flutter 自定义 HttpClient 请求构建
 *   2. Dart 层 SSL Pinning（证书 SHA-256 校验）
 *   3. Dart Isolate 内签名计算
 *   4. Dart↔C FFI 边界分析
 *
 * 反逆向对抗：
 *   - ptrace/TracerPid 检测调试附加
 *   - /proc/self/maps 扫描 Frida 特征
 *   - 27042-27044 端口探测
 *   - 线程名扫描
 *   - 检测命中即静默投毒密钥一字节
 *
 * 标记：Fatdog_haze（真）/ Fatdog_fog（诱饵）
 */
public class FlutterNet {
    static {
        System.loadLibrary("flutternet");
    }

    private FlutterNet() {}

    // ==================== 静态注册方法（标准 JNI 命名） ====================

    /**
     * 构建带签名的请求参数（模拟 Flutter HttpClient 构建）
     * @param page 页码
     * @param ts   时间戳
     * @return 签名后的请求参数字节数组
     */
    public static native byte[] nativeBuildRequest(int page, long ts);

    /**
     * 返回 SSL Pinning 证书哈希（教学用途）
     * @return 证书 SHA-256 哈希字符串
     */
    public static native String nativeGetPinHash();

    // ==================== 动态注册方法（JNI_OnLoad RegisterNatives） ====================

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
     * 返回反调试自检状态（调试/教学用）
     * @return 状态字符串
     */
    public static native String nativeGetStatus();
}
