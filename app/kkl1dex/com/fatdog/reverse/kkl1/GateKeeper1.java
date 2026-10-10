package com.fatdog.reverse.kkl1;

import java.security.MessageDigest;

/**
 * 玄冥渊 · 业务真身（KKL1）——独立编译成第二个 dex，构建期整体加密埋进
 * assets/kkl1/abyss_vein.bin，运行时由 libkkl1.so nativeUnseal() 解密 →
 * 落盘 → DexClassLoader 加载（一代壳的经典破绽：解密后的 dex 会躺在磁盘上）。
 *
 * 本类绝不进入主 classes.dex：主 dex 只能通过反射见到它。
 * 取数签名逻辑全部在这里：sign(seal, ts, page) = md5(hex(seal) + "page=N&ts=T")，
 * seal 由 libkkl1.so nativeDeriveSeal() 派生（真标记藏 UTF-16，明文拿不到）。
 * 注意：这里用的是古典摘要（MD5）做校验串，不是 HMAC。
 */
public final class GateKeeper1 {

    /** dump 后快速确认身份用的标记串 */
    public static String magic() {
        return "XuanMingYuan:GateKeeper1";
    }

    /** 取数签名：md5(hex(seal) + "page=N&ts=T")，hex 小写输出；非 HMAC 构造。 */
    public static String sign(byte[] seal, long ts, int page) {
        try {
            StringBuilder hex = new StringBuilder();
            for (byte b : seal) {
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

    /** 纯 Java 自校验：seal 是否 16 字节（提示玩家密钥形状） */
    public static boolean sealLooksValid(byte[] seal) {
        return seal != null && seal.length == 16;
    }
}
