package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 第六片：形态。
 *
 * 确认累计下来的总数是不是个正经数（非负、不越界）。
 * 教学性校验，不参与密钥。
 */
public final class GateKeeper4f {
    private GateKeeper4f() {}

    /** 总数形态：非负即算过。 */
    public static boolean sumLooksValid(long sum) {
        return sum >= 0L;
    }

    /** 总数转十进制字符串。 */
    public static String sumText(long sum) {
        return String.valueOf(sum);
    }
}
