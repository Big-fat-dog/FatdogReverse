package com.fatdog.reverse;

// 诱饵类：名字带 ad 语义但不起眼，里面也有一个开关字段。
// 改它一点用都没有——AdBox 从不读这里。正解是找 AdBox 里那个短名开关 `a`。
public class PhantomAd {
    public static int enabled = 1;        // 假开关：把 1 改成 0，广告照样弹
    static final String TAG = "ad_ctrl";
    static final int[] SHIELD = {171, 196, 205, 232, 168, 245, 199, 171, 220, 235};

    static String grumble() {
        return "◇ " + Sx.s(SHIELD) + " ◇";
    }
}