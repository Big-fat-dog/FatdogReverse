package com.fatdog.reverse;

// 签名校验对抗第四课：L4 派生型——密钥由证书哈希派生。
// key = SHA256(certDER ‖ "Fatdog_bind")，直接作 HMAC-SHA256 签名。
// 没有任何 if 判断签名对错——重打包者的证书派生出的 key 必然不同，服务端全部 403 零提示。
// 正解唯一：偷出 App 运行时算出的真实 certHash，带真哈希离线复刻整条链取数。
public class Wg {
    static {
        System.loadLibrary("amber");
    }

    private Wg() {
    }

    /** 传入 DER → 计算派生密钥 → 返回 32 字节派生密钥 */
    public static native byte[] nativeKeySeed(byte[] der);

    /** HMAC-SHA256(g_key, "page=N&ts=T") → hex string */
    public static native String nativeSign(int page, long ts);
}
