package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5c —— 报文模板。
 * 只负责拼出要交给内核签名的请求串，真正加密签名在 native。
 */
public final class GateKeeper5c {

    private GateKeeper5c() {}

    public static String build(int page, long ts) {
        return "page=" + page + "&ts=" + ts;
    }
}
