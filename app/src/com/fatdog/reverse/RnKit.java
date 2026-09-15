package com.fatdog.reverse;

/**
 * KL41 诱饵类（须弥界 · JS Bundle 基础）
 * 假签名工具——内容像真的，但无人调用。
 *
 * 标记：Fatdog_plan（诱饵，与真标记仅差后缀）
 */
public class RnKit {
    private static final String FAKE_KEY = "Fatdog_plan";
    private static final String FAKE_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private RnKit() {}

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

    public static String getPinHash() {
        return FAKE_PIN;
    }
}
