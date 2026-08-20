package com.fatdog.reverse;

import android.os.Build;

import java.util.Locale;

// 环境探测：模拟器走 10.0.2.2（宿主回环），真机走 127.0.0.1（配 adb reverse）。
// 识别不出模拟器特征时按真机处理（默认真机）。
public class NetHost {
    public static boolean isEmulator() {
        String low = (Build.FINGERPRINT + "|" + Build.PRODUCT + "|" + Build.MODEL + "|"
                + Build.HARDWARE + "|" + Build.MANUFACTURER + "|" + Build.DEVICE + "|" + Build.BOARD)
                .toLowerCase(Locale.US);
        return low.contains("generic") || low.contains("emulator") || low.contains("goldfish")
                || low.contains("ranchu") || low.contains("vbox") || low.contains("sdk_gphone")
                || low.contains("ttvm") || low.contains("nox") || low.contains("mumu")
                || low.contains("ldplayer");
    }

    public static String host() {
        return isEmulator() ? "10.0.2.2" : "127.0.0.1";
    }

    public static String httpBase() {
        return "http://" + host() + ":8787";
    }

    public static String httpsBase() {
        return "https://" + host() + ":8443";
    }

    // config.json 的 api_base_url 填 "AUTO"（或空）→ 按环境自动；否则用配置的地址（如局域网 IP 覆盖）。
    public static String resolve(String configured, boolean https) {
        if (configured == null) {
            return https ? httpsBase() : httpBase();
        }
        String v = configured.trim();
        if (v.length() == 0 || v.equalsIgnoreCase("AUTO")) {
            return https ? httpsBase() : httpBase();
        }
        return configured;
    }
}
