package com.fatdog.reverse;

import org.json.JSONArray;
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

// KL44 暗流涌动（须弥界 · JSBridge 签名拦截 + JS 层加密）的 JNI 桥 + 网络助手。
// 第一层（JS，混淆在页面里）把明文参数 RC4 成 enc；第二层（libsignbridge.so）用藏在 so 里的钥
// 对 "page=..&ts=..&enc=.." 再做一次 HMAC-SHA256。so 里还有 ptrace/maps 反调试，被调则改用诱饵钥。
public class SignBridge {
    static {
        System.loadLibrary("signbridge");
    }

    private SignBridge() {}

    // 第二层：native 对（page, ts, enc）做 HMAC-SHA256；若判定被调试则用诱饵钥
    public static native String nativeBridgeSign(int page, long ts, String enc);

    // 本地验签
    public static native boolean nativeVerify(int page, long ts, String enc, String sign);

    // 只读自检：只报告守卫命中了几个信号
    public static native String nativeStatus();

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

    // 双层结果一并提交：enc（JS 层密文）+ sign（native 层签名）
    static void fetch(String base, int page, long ts, String enc, String sign, final Cb cb) {
        try {
            final OkHttpClient c = trustClient();
            FormBody form = new FormBody.Builder()
                    .add("page", String.valueOf(page))
                    .add("ts", String.valueOf(ts))
                    .add("enc", enc)
                    .add("sign", sign)
                    .build();
            Request req = new Request.Builder()
                    .url(base + "/api/kl44")
                    .header("User-Agent", "Fatdog/1.0 (Android)")
                    .post(form)
                    .build();
            c.newCall(req).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, java.io.IOException e) {
                    cb.onError(e == null ? "网络错误" : e.getMessage());
                }

                @Override
                public void onResponse(Call call, Response response) {
                    try (ResponseBody body = response.body()) {
                        String text = body == null ? "" : body.string();
                        if (!response.isSuccessful()) {
                            cb.onError("HTTP " + response.code());
                            return;
                        }
                        JSONObject obj = new JSONObject(text);
                        JSONArray arr = obj.getJSONArray("nums");
                        int[] nums = new int[arr.length()];
                        for (int i = 0; i < arr.length(); i++) nums[i] = arr.getInt(i);
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
