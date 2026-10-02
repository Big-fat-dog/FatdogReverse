package com.fatdog.reverse;

// 签名校验对抗第四课：L4 派生型——密钥由证书派生。
// key = SHA256(原包 certHash ‖ 标记 ‖ vt)，直接作 HMAC-SHA256 签名。
// 没有任何 if 判断签名对错——重打包者的证书摘要不同→派生 key 不同→服务端必然对不上。
// 正解：让 nativeKeySeed 吃到"原包证书"，或直接偷出 App 运行时算出的真实 certHash。
//
// 2026-10-02 双层链路：① so 内一个纯开关常量（g_door）——门不开 nativeSign 返回空串、取不到数；
//   ② nativeKeySeed 比对当前包证书 → 不过则派生落到诱饵标记 Fatdog_band → 服务端回脏数据；
//   ③ nativeVerdictToken() 产出一次性令牌 vt（参与密钥派生）。
public class Wg {
    static {
        System.loadLibrary("amber");
    }

    private Wg() {
    }

    /** 递入当前包的证书 DER：native 内记账(ticks++)、摘要、与基准比对，并返回派生密钥字节 */
    public static native byte[] nativeKeySeed(byte[] der);

    /** HMAC-SHA256(key, "nonce=<n>&page=<p>&ts=<t>") → hex（被签串按字典序）；① 门未开返回空串 */
    public static native String nativeSign(int page, long ts, String nonce, String vt);

    /** ③ 取数令牌：门未开返回空串（取不到数）；门已开返回 16 位 hex 一次性令牌 */
    public static native String nativeVerdictToken();

    public static String verdictToken() {
        String t = nativeVerdictToken();
        return t == null ? "" : t;
    }
}
