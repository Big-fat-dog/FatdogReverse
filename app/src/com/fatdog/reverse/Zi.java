package com.fatdog.reverse;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
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
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 34 的发包器：POST 表单 page/ts/enc/sign(+dev/ver 噪声)；
// enc/sign 由 Yh 动态注册的真身计算，响应 {"d":hex} 经 nativeUnwrap 解 RC4。
public class Zi {
    static final String BASE = NetHost.httpsBase();

    public interface Cb {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    private static OkHttpClient client;

    private static synchronized OkHttpClient trustClient() throws Exception {
        if (client != null) return client;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ca = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(Tm.caDer()));
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("fatdog", ca);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, tmf.getTrustManagers(), new SecureRandom());
        HostnameVerifier hv = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return NetHost.host().equals(hostname);
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
        final long ts = System.currentTimeMillis() / 1000;
        final String enc = Yh.nativePack(page, ts);
        final String sign = Yh.nativeSign(enc);
        if (!Yh.assertGuard(page)) {            // 签后过闸：ticks 先随真身递增
            cb.onError("完整性校验失败：校验链被篡改");
            return;
        }
        try {
            final OkHttpClient c = trustClient();
            FormBody body = new FormBody.Builder()
                    .add("page", String.valueOf(page))
                    .add("ts", String.valueOf(ts))
                    .add("enc", enc)
                    .add("sign", sign)
                    .add("dev", "fatdog-sim")
                    .add("ver", "3.4")
                    .build();
            Request req = new Request.Builder()
                    .url(base + "/api/l34")
                    .post(body)
                    .header("User-Agent", "Fatdog/1.0 (Android)")
                    .build();
            c.newCall(req).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, java.io.IOException e) {
                    cb.onError(e == null ? "网络错误" : e.getMessage());
                }

                @Override
                public void onResponse(Call call, Response response) {
                    try (ResponseBody rb = response.body()) {
                        String text = rb == null ? "" : rb.string();
                        if (!response.isSuccessful()) {
                            cb.onError("HTTP " + response.code() + ": " + text);
                            return;
                        }
                        JSONObject obj = new JSONObject(text);
                        String d = obj.optString("d", "");
                        if (d.length() == 0) {
                            cb.onError("响应缺少密文 d");
                            return;
                        }
                        String plain = Yh.nativeUnwrap(d);      // RC4 解包在 native
                        int bar = plain.indexOf('|');
                        if (!plain.startsWith("page=") || bar < 0) {
                            cb.onError("响应解包失败");
                            return;
                        }
                        int got = Integer.parseInt(plain.substring(5, bar));
                        String list = plain.substring(bar + 5); // 跳过 "nums="
                        String[] parts = list.split(",");
                        int[] nums = new int[parts.length];
                        for (int i = 0; i < parts.length; i++) nums[i] = Integer.parseInt(parts[i].trim());
                        cb.onPage(got, nums);
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
