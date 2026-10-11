package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务真身主编排（KKL5）。
 *
 * 本类不进主 classes.dex：构建期被复合加密（内层分组 + 外层流式）分段埋进
 * assets/kkl5/，运行时由 libspindle.so 的 nativeFold() 解密后经内存加载。
 * 密钥由内存机 VM 派生，壳层密钥逐层域分离。
 *
 * fetch 是取数唯一入口：串起 5a..5l 各片的职责，最终调 5l 的 native 方法签名。
 */
public final class GateKeeper5 {

    private GateKeeper5() {}

    /** 主编排取数入口：page/ts → 校验页码 → 拼报文 → native 签名。 */
    public static String fetch(int page, long ts) {
        if (!GateKeeper5b.pageOk(page)) return "";
        String payload = GateKeeper5c.build(page, ts);
        if (payload == null || payload.length() < 8) return "";
        String token = GateKeeper5l.nativeSign(page, ts);
        if (token == null) return "";
        int bar = token.indexOf('|');
        if (bar <= 0) return "";
        String enc = token.substring(0, bar);
        String sign = token.substring(bar + 1);
        if (!GateKeeper5h.signed(enc, sign)) return "";
        return token;
    }

    /** dump 后确认身份。 */
    public static String magic() {
        return GateKeeper5a.magic();
    }
}
