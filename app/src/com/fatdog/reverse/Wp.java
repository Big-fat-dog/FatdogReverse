package com.fatdog.reverse;

// 签名校验对抗第五课：幽冥合卷——收官综合卷。
// 四重防线：守卫矩阵（启动记账 → Activity 核账 → 当前包证书摘要 → 基准数组 CRC）
//          + 证书摘要参与密钥派生 + 响应 AES 加密。
// 任一环节不满足 → 派生落到诱饵标记 Fatdog_steal → 服务端回【脏数据】（静默喂假数据）。
//
// 2026-10-02 双层链路：① so 内一个纯开关常量（g_door）——门不开则一切取值入口返回空；
//   ② 守卫矩阵里补上了「当前包证书摘要比对」（原先只查 guard 函数有没有被调用，
//      重打包者原样保留调用即可通过，证书其实从未参与判定）；
//   ③ nativeVerdictToken() 产出一次性令牌 vt，参与密钥派生。
public class Wp {
    static {
        System.loadLibrary("felix");
    }

    private Wp() {
    }

    /** 启动记账：递增审计计数（并确认 CRC 检查就绪） */
    public static native void nativeAudit();

    /** 递入当前包的证书 DER：native 内摘要并与内置基准比对，纳入守卫矩阵 */
    public static native void nativeSeed(byte[] der);

    /** 核账：传入 tick + recheck，返回 true = 守卫矩阵全过，false = 已转入诱饵路径 */
    public static native boolean nativeGuard(int tick, int recheck);

    /** ③ 取数令牌：门未开返回空串（取不到数）；门已开返回 16 位 hex 一次性令牌 */
    public static native String nativeVerdictToken();

    /** 签名 + AES 加密，返回 [sign_hex, enc_hex]；① 门未开返回空数组 */
    public static native String[] nativeSignAndEnc(int page, long ts, String vt);

    /** AES-ECB 解密 hex 密文 → 明文字符串（需带该次请求用的 vt 复算密钥） */
    public static native String nativeDecrypt(String hexCipher, String vt);

    public static String verdictToken() {
        String t = nativeVerdictToken();
        return t == null ? "" : t;
    }
}
