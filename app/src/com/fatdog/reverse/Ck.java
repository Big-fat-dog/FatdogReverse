package com.fatdog.reverse;

/**
 * 天机阁 KL30 天机织锦 JNI 桥：Protobuf 二进制协议。
 * libloom.so 导出：
 *   byte[] nativeBuildRequest(int page, long ts)  — 编码 PageRequest protobuf
 *   boolean nativeVerifyResponse(byte[] data)     — 验证响应 code==0 && nums 非空
 *   int[]    nativeParseNums(byte[] data)          — 从响应中提取 nums 数组
 *   String   nativeAnswer()                        — 最终答案
 */
public class Ck {
    static { System.loadLibrary("loom"); }

    public static native byte[] nativeBuildRequest(int page, long ts);
    public static native boolean nativeVerifyResponse(byte[] data);
    public static native int[] nativeParseNums(byte[] data);
    public static native String nativeAnswer();
}
