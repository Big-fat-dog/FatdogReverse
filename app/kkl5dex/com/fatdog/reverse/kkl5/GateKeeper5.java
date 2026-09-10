package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务真身（KKL5）。
 *
 * 本类不进主 classes.dex：构建期被 AES-128-CBC 加密埋进
 * assets/kkl5/ascension_altar.bin，运行时由 libkkl5.so 的 nativeUnseal()
 * 解密后经 InMemoryDexClassLoader 内存加载。密钥由 onCreate VM 门禁派生。
 */
public final class GateKeeper5 {

    private GateKeeper5() {}

    /** dump 后确认身份用的标记串。 */
    public static String magic() {
        return "ZhuXianTai:GateKeeper5";
    }

    /** onCreate 还原链路自检：VMP 解释器输出的指纹必须齐全。 */
    public static boolean gateLooksValid(int vmSteps, boolean halted) {
        return halted && vmSteps >= 100;
    }

    /** 复合签名存在性检查（真正签名在 native）。 */
    public static boolean signed(String enc, String sign) {
        return enc != null && sign != null && enc.length() >= 32 && sign.length() == 64;
    }
}
