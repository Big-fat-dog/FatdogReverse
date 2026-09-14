package com.fatdog.reverse;

/**
 * KL40 星河倒影（碧落天 · 综合收官卷）
 * JNI 桥类：多层安全叠加——AOT 加密 + FFI + Dart Isolate 签名 + 反调试 + 证书锁定 + RC4 响应
 *
 * 动态注册（JNI_OnLoad RegisterNatives）：
 *   nativeFullSign / nativeDecryptRsp / nativeVerifyIntegrity / nativeAnswer / nativeGetStatus
 *
 * 考点：
 *   1. 多层安全叠加——任一层被绕过即静默投毒
 *   2. AOT 编译产物加密 + FFI 动态链接
 *   3. Dart Isolate 多线程签名 + 证书锁定 + HMAC 签名链
 *   4. 响应体 RC4 加密
 *   5. 反调试（ptrace + timing）+ 自校验
 *
 * 标记：Fatdog_reflect（真）/ Fatdog_echo（诱饵）
 */
public class FlutterMirror {
    static {
        System.loadLibrary("rig");
    }

    private FlutterMirror() {}

    // ==================== 动态注册方法（JNI_OnLoad RegisterNatives） ====================

    /**
     * 全链签名（AOT + FFI + Isolate + HMAC 综合签名）
     * 调用前会执行反调试检测 + 自校验，检测到逆向即投毒
     *
     * @param page 页码
     * @param ts   时间戳
     * @return 签名字符串（检测触发返回 "guard_failed"）
     */
    public static native String nativeFullSign(int page, long ts);

    /**
     * RC4 解密响应体
     * @param hex_data 十六进制编码的 RC4 密文
     * @return 解密后的明文 JSON
     */
    public static native String nativeDecryptRsp(String hex_data);

    /**
     * 自校验（.text 段哈希 + 函数指针校验）
     * @return true 如果代码完整性正常
     */
    public static native boolean nativeVerifyIntegrity();

    /**
     * 返回答案（本地比对用）
     * @return 答案字符串（8位hex）
     */
    public static native String nativeAnswer();

    /**
     * 返回反调试自检 + 完整性校验状态
     * @return 状态字符串
     */
    public static native String nativeGetStatus();
}
