package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 第三片：报文。
 *
 * 只负责把「页码 + 时间戳」拼成取数用的原始报文。
 * 它不知道密钥，也不知道签名，只吐一句话。
 */
public final class GateKeeper4c {
    private GateKeeper4c() {}

    /** 报文格式串（%d 页码，%d 时间戳）。 */
    public static String shape() {
        return "page=%d&ts=%d";
    }

    /** 拼装报文。 */
    public static String build(int page, long ts) {
        return String.format(java.util.Locale.US, shape(), page, ts);
    }
}
