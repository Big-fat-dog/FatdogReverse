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
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 碧落天 KL37「风中鸢尾」的 JNI 桥 + 网络助手。
// 请求参数由伴生 so 出密文；题眼在随包发出的真实 Flutter 载荷里，且该载荷经过符号混淆。
public class FlutterCore {
    static {
        System.loadLibrary("fluttercore");
    }

    private FlutterCore() {
    }

    // 本关的"签名"就是密文本身（本关只用一种对称加密）
    public static native String nativeEnc(int page, long ts);

    // 本地提交比对值
    public static native String nativeAnswer();

    // 只读自检：只报密码原语与自检结果，不含密钥明文、不判胜
    public static native String nativeGetStatus();

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
        final String enc = FlutterCore.nativeEnc(page, ts);
        try {
            final OkHttpClient c = trustClient();
            String url = base + "/api/kl37?page=" + page + "&ts=" + ts + "&enc=" + enc;
            Request req = new Request.Builder()
                    .url(url)
                    .header("User-Agent", "Fatdog/1.0 (Android)")
                    .get()
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
                            cb.onError("HTTP " + response.code() + ": " + text);
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
