package com.fatdog.reverse;

/**
 * KL42 诱饵类（须弥界 · H5 资源加密）。
 * 名字贴着考点、内容像真的——但没有任何调用方。
 *
 * 标记：Fatdog_shore（诱饵，与真钥仅差几个字母）
 */
public class BeachKit {
    private static final String FAKE_KEY = "Fatdog_shore";
    private static final String FAKE_TAG = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    private BeachKit() {}

    public static String fakeSign(int page, long ts) {
        String msg = "page=" + page + "&ts=" + ts;
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
