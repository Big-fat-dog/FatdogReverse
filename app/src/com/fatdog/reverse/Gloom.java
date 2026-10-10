package com.fatdog.reverse;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;

// 抓包环境体检（KL38「雾外之障」）：查"出关的信是否被引到了明处的驿站"——
// 系统代理 / 默认代理 / VPN 传输。返回命中数，交由 native 合并评分。
// 说明：这不是"反调试"，只做只读环境感知，命中后由 native 侧决定投毒与否。
public class Gloom {
    private Gloom() {
    }

    // 返回命中数（0..3）。任一路读不到都不记分（三态，防 ROM/容器误报）。
    public static int scan(Context ctx) {
        int hits = 0;
        // ① 系统代理属性（无需权限）
        try {
            String h1 = System.getProperty("http.proxyHost");
            String h2 = System.getProperty("https.proxyHost");
            String p1 = System.getProperty("http.proxyPort");
            String p2 = System.getProperty("https.proxyPort");
            if (nonEmpty(h1) || nonEmpty(h2) || nonEmpty(p1) || nonEmpty(p2)) hits++;
        } catch (Throwable ignored) {
        }
        // ② / ③ ConnectivityManager：默认代理 + VPN 传输
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                Network[] nets = cm.getAllNetworks();
                boolean proxy = false;
                boolean vpn = false;
                if (nets != null) {
                    for (Network n : nets) {
                        if (n == null) continue;
                        LinkProperties lp = cm.getLinkProperties(n);
                        if (lp != null && lp.getHttpProxy() != null) proxy = true;
                        NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                        if (nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) vpn = true;
                    }
                }
                if (proxy) hits++;
                if (vpn) hits++;
            }
        } catch (Throwable ignored) {
        }
        return hits;
    }

    private static boolean nonEmpty(String s) {
        return s != null && s.trim().length() > 0;
    }
}
