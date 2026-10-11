package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5h —— 签名形态校验。
 * 取数内核返回的 enc|sign 形态检查（真正加解密在 native）。
 */
public final class GateKeeper5h {

    private GateKeeper5h() {}

    public static boolean signed(String enc, String sign) {
        return enc != null && sign != null && enc.length() >= 32 && sign.length() == 32;
    }
}
