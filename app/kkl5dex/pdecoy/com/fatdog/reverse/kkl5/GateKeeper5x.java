package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 明文诱饵（GateKeeper5x）。
 * 同名同形的假 GateKeeper5：fetch 恒返回空串，magic 也是错的——
 * 钓"抓到第一个业务类就收工"的人。
 */
public final class GateKeeper5x {

    private GateKeeper5x() {}

    public static String fetch(int page, long ts) {
        return "";
    }

    public static String magic() {
        return "ZhuXianTai:DecoyShell";
    }
}
