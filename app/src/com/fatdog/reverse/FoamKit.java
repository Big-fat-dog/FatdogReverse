package com.fatdog.reverse;

/**
 * KL44 诱饵类（须弥界 · JSBridge 签名拦截）。
 * 名字贴着考点、内容像真的——但没有任何调用方。
 *
 * 标记：Fatdog_foam（诱饵，与真钥仅差几个字母）
 */
public class FoamKit {
    private static final String FAKE_KEY = "Fatdog_foam";
    private static final String FAKE_TAG = "sha256/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=";

    private FoamKit() {}

    public static String fakeSign(int page, long ts, String enc) {
        String msg = "page=" + page + "&ts=" + ts + "&enc=" + enc;
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(FAKE_KEY.getBytes(), "HmacSHA256"));
            byte[] raw = mac.doFinal(msg.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : raw) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public static String getTag() {
        return FAKE_TAG;
    }
}
