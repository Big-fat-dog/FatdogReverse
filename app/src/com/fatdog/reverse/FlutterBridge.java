package com.fatdog.reverse;

/**
 * KL36 云中锦书（碧落天 · Flutter/Dart 常量池模拟）
 * JNI 桥类：loadLibrary("flutterbridge")
 * 导出函数：nativeGetConstantPool / nativeSign / nativeVerify / nativeAnswer
 */
public class FlutterBridge {
    static {
        System.loadLibrary("flutterbridge");
    }
    
    /**
     * 获取常量池数据（模拟 Dart AOT 编译后的常量池片段）
     * @return 常量池字节数组
     */
    public static native byte[] nativeGetConstantPool();
    
    /**
     * 用提取的密钥计算 HMAC-SHA256 签名
     * @param page 页码
     * @param ts 时间戳
     * @return 签名字符串
     */
    public static native String nativeSign(int page, long ts);
    
    /**
     * 验证签名是否正确
     * @param page 页码
     * @param ts 时间戳
     * @param sign 待验证的签名
     * @return true 如果签名正确
     */
    public static native boolean nativeVerify(int page, long ts, String sign);
    
    /**
     * 返回答案（本地比对用）
     * @return 答案字符串
     */
    public static native String nativeAnswer();
}
