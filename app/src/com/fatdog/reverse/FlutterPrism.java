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

// 碧落天 KL40b「镜中之障」的 JNI 桥 + 网络助手。
// 本关的证书校验在"引擎"那一层（native 内部，Java/钩子够不着）——
// 取数参数由伴生 so 出密文与摘要；引擎校验未放行时，参数被静默投毒（服务端不认）。
public class FlutterPrism {
    static {
        System.loadLibrary("prism");
    }

    private FlutterPrism() {
    }

    // 请求参数：enc = RC4(...)，sign = md5(enc + 主密钥)
    public static native String nativeEnc(int page, long ts);

    public static native String nativeSign(int page, long ts, String enc);

    // 只读展示：引擎校验是否已放行（中性，不点破手段、不判胜）
    public static native String nativeGetProbe();

    // 本地提交比对值
    public static native String nativeAnswer();

    // 只读自检
    public static native String nativeGetStatus();

    static final String BASE = NetHost.httpsBase();

    public interface Cb {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    private static OkHttpClient client;

    private static synchronized OkHttpClient tlsClient() throws Exception {
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
        final X509TrustManager base = (X509TrustManager) tmf.getTrustManagers()[0];
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new javax.net.ssl.TrustManager[]{base}, new SecureRandom());
        HostnameVerifier hv = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return NetHost.host().equals(hostname);
            }
        };
        client = new OkHttpClient.Builder()
                .sslSocketFactory(sc.getSocketFactory(), base)
                .hostnameVerifier(hv)
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
        return client;
    }

    static void fetchPage(String base, final int page, final Cb cb) {
        final long ts = System.currentTimeMillis() / 1000;
        final String enc;
        final String sign;
        try {
            enc = FlutterPrism.nativeEnc(page, ts);
            sign = FlutterPrism.nativeSign(page, ts, enc);
        } catch (Throwable t) {
            cb.onError("参数构造失败");
            return;
        }
        try {
            final OkHttpClient c = tlsClient();
            String url = base + "/api/kl40b?page=" + page + "&ts=" + ts + "&enc=" + enc + "&sign=" + sign;
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
