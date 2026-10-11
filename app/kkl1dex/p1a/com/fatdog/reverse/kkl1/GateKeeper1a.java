package com.fatdog.reverse.kkl1;

/**
 * 玄冥渊 · 业务分片其一（1a）。
 *
 * 真身不再是一个完整 dex，而是两片各自落盘、按序加载。本片只挂最浅的
 * 一层——身份串与形状自检，取数签名不在这里。独立编译成一个 dex，
 * 构建期整体加密后埋进 assets/kkl1/abyss_vein.bin。
 *
 * 本类绝不进入主 classes.dex：主 dex 只能经反射见到它。
 */
public final class GateKeeper1a {

    /** 身份串：找到这一片时用来对号（不是密钥） */
    public static String magic() {
        return "XuanMingYuan:GK1a";
    }

    /** 形状自检：标记是否 16 字节（只提示形状，不做校验） */
    public static boolean shape(byte[] mark) {
        return mark != null && mark.length == 16;
    }

    private GateKeeper1a() {}
}
