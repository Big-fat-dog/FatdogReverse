package com.fatdog.reverse.kkl2;

import java.security.MessageDigest;

/**
 * 万剑冢 · 业务真身（KKL2）——独立编译成第二个 dex，构建期用 AES-128-CBC 整体加密后
 * 埋进 assets/kkl2/echoes_of_blades.bin，运行时由 libkkl2.so nativeUnseal() 解密 →
 * InMemoryDexClassLoader 内存加载（不落盘）。
 *
 * 本类绝不进入主 classes.dex：主 dex 只能通过反射见到它。
 * 取数验签逻辑全部在这里：sign = MD5( hex(key) + "page=N&ts=T" )（MD5 古典摘要，非 HMAC），
 * key 由 libkkl2.so nativeDeriveSeal() 派生（真标记藏 UTF-16，明文拿不到）。
 */
public final class GateKeeper2 {

    /** dump 后快速确认身份用的标记串 */
    public static String magic() {
        return "WanJianZang:GateKeeper2";
    }

    /** MD5 签名，hex 小写输出：md5( hex(key) + "page=N&ts=T" ) */
    public static String sign(byte[] key, long ts, int page) {
        try {
            StringBuilder hex = new StringBuilder();
            for (byte b : key) {
                hex.append(String.format("%02x", b & 0xff));
            }
            String payload = hex.toString() + "page=" + page + "&ts=" + ts;
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] out = md.digest(payload.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : out) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /** 纯 Java 自校验：key 是否 16 字节（提示玩家密钥形状 = AES-128 / MD5 摘要长度） */
    public static boolean keyLooksValid(byte[] key) {
        return key != null && key.length == 16;
    }
}
