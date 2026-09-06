package com.fatdog.reverse.kkl2;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 万剑冢 · 业务真身（KKL2）——独立编译成第二个 dex，构建期加密埋进 assets，
 * 运行时由 libkkl2.so nativeUnseal() 解密 → InMemoryDexClassLoader 内存加载。
 *
 * 本类绝不进入主 classes.dex：主 dex 只能通过反射见到它。
 * 取数验签逻辑全部在这里：HMAC-SHA256(key, "page=N&ts=T")，
 * key 由 libkkl2.so nativeDeriveKey() 派生（真标记藏 UTF-16，明文拿不到）。
 */
public final class GateKeeper2 {

    /** dump 后快速确认身份用的标记串 */
    public static String magic() {
        return "WanJianZang:GateKeeper2";
    }

    /** 标准 HMAC-SHA256，hex 小写输出 */
    public static String sign(byte[] key, long ts, int page) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            String payload = "page=" + page + "&ts=" + ts;
            byte[] out = mac.doFinal(payload.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : out) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /** 纯 Java 自校验：key 是否 32 字节（提示玩家密钥形状） */
    public static boolean keyLooksValid(byte[] key) {
        return key != null && key.length == 32;
    }
}
