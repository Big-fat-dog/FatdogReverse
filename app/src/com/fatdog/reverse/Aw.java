package com.fatdog.reverse;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 24 的 TLS 客户端：自定义 TrustManager（信内置 CA，复用 Tm.caDer()）+ 自定义
// HostnameVerifier 做 pin 校验。校验路径：verify() 算服务器证书 SPKI -> Z24Core.checkPin()
// （守卫计数 +1 再比较）。响应解析前 Z24Core.assertGuard()：计数为 0 或结论为假 =
// 校验链被篡改（Hook 掉校验函数直接放行会被抓住）。
// 请求走 HTTPS:8443 的 /api/swap，HMAC 密钥前半段 Tk，后半段 "swap_key" 在这里。
public class Aw {
    static final String BASE = NetHost.httpsBase();   // 主机自动选择：模拟器 10.0.2.2 / 真机 127.0.0.1

    public interface Cb {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    // HMAC 密钥后半段 "swap_key"（^0x3C）
    static final int[] KB = {79, 75, 93, 76, 99, 87, 89, 69};

    private static OkHttpClient client;

    static String buildKey() {
        return Tk.partA() + new String(dec(KB, 0x3C));
    }

    static String sign(int page, long ts) {
        return Tk.hmacSha256Hex(buildKey(), "page=" + page + "&ts=" + ts);
    }

    private static byte[] dec(int[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return out;
    }

    private static synchronized OkHttpClient guardedClient() throws Exception {
        if (client != null) {
            return client;
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ca = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(Tm.caDer()));
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("fatdemo", ca);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, tmf.getTrustManagers(), new SecureRandom());

        // 反 Hook 守卫的触发面：verify 内部必须真实走一遍 checkPin。
        HostnameVerifier hv = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                try {
                    Certificate[] chain = session.getPeerCertificates();
                    if (chain == null || chain.length == 0) {
                        return false;
                    }
                    return Z24Core.checkPin(Z24Core.spkiSha256((X509Certificate) chain[0]));
                } catch (Exception e) {
                    return false;
                }
            }
        };

        client = new OkHttpClient.Builder()
                .sslSocketFactory(sc.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0])
                .hostnameVerifier(hv)
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
        return client;
    }

    static void fetchPage(String base, final int page, final Cb cb) {
        try {
            final OkHttpClient c = guardedClient();
            long ts = System.currentTimeMillis() / 1000;
            String url = base + "/api/swap?page=" + page + "&ts=" + ts + "&sign=" + sign(page, ts);
            Request req = new Request.Builder()
                    .url(url)
                    .header("User-Agent", "Fatdemo/1.0 (Android)")
                    .get()
                    .build();
            c.newCall(req).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, java.io.IOException e) {
                    cb.onError(e == null ? "网络错误" : e.getMessage());
                }

                @Override
                public void onResponse(Call call, Response response) {
                    try {
                        Z24Core.assertGuard();
                    } catch (IllegalStateException e) {
                        cb.onError(e.getMessage());
                        return;
                    }
                    try (ResponseBody body = response.body()) {
                        String text = body == null ? "" : body.string();
                        if (!response.isSuccessful()) {
                            cb.onError("HTTP " + response.code() + ": " + text);
                            return;
                        }
                        JSONObject obj = new JSONObject(text);
                        org.json.JSONArray arr = obj.getJSONArray("nums");
                        int[] nums = new int[arr.length()];
                        for (int i = 0; i < arr.length(); i++) {
                            nums[i] = arr.getInt(i);
                        }
                        cb.onPage(obj.getInt("page"), nums);
                    } catch (Exception e) {
                        cb.onError(e == null ? "响应解析失败" : e.getMessage());
                    }
                }
            });
        } catch (Exception e) {
            cb.onError(e == null ? "TLS 初始化失败" : e.getMessage());
        }
    }
}
