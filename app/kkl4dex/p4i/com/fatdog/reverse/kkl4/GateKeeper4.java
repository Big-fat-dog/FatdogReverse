package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 第九片：主编排（取数入口）。
 *
 * 把前面八片串成一条取数链：验页码 → 拼报文 → 调第八片的 native 签名。
 * 玩家必须 dump 齐九片、并让门面 so 完成 nativeBind，才能真正取回一页数。
 */
public final class GateKeeper4 {
    private GateKeeper4() {}

    /** 主编排：验页码，返回取数签名 "enc|sign"；页码非法返回空串。 */
    public static String fetch(int page, long ts) {
        if (!GateKeeper4b.pageOk(page)) {
            return "";
        }
        // 报文由第三片拼，但真正加密在第八片的 native 侧；
        // 这里仅确保链路完整，避免把第三片晾在一边。
        String probe = GateKeeper4c.build(page, ts);
        if (probe == null || probe.isEmpty()) {
            return "";
        }
        return GateKeeper4h.nativeSign(page, ts);
    }

    /** dump 后确认身份用的标记串。 */
    public static String magic() {
        return GateKeeper4a.magic();
    }
}
