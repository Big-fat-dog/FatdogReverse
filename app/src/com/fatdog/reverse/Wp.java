package com.fatdog.reverse;

// 签名校验对抗第五课：幽冥合卷——收官综合卷。
// 三点互验记账（Application 记账 → Activity 核账 → native 再核账互锁）
// + CRC 自校验基线 + certHash 参与密钥派生 + 响应 AES 加密。
// 任一环节缺失 → 静默投毒一字节。
public class Wp {
    static {
        System.loadLibrary("m9");
    }

    private Wp() {
    }

    /** Application 启动时调用，递增审计计数 */
    public static native void nativeAudit();

    /** Activity 核账：传入 tick + recheck，返回 true = 正常，false = 已投毒 */
    public static native boolean nativeGuard(int tick, int recheck);

    /** HMAC-SHA256(g_hmac_key, "page=N&ts=T") → hex string */
    public static native String nativeSign(int page, long ts);

    /** 签名 + AES 加密，返回 [sign_hex, enc_hex] */
    public static native String[] nativeSignAndEnc(int page, long ts);

    /** AES-ECB 解密 hex 密文 → 明文字符串 */
    public static native String nativeDecrypt(String hexCipher);
}
