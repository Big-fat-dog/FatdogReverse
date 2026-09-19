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

// 碧落天 KL40「星河倒影」的 JNI 桥 + 网络助手（综合收官卷）。
// 三原语叠加：请求用 AES-GCM 封（带完整性标签），签名用普通 MD5，
// 而**响应体换了一把 AES 密钥**回来，必须解开才看得到数字。
public class FlutterMirror {
    static {
        System.loadLibrary("rig");
    }

    private FlutterMirror() {
    }

    // 请求加密：enc = hex(nonce(12) || ct || tag(16))，算法 AES-256-GCM
    public static native String nativeEnc(int page, long ts);

    // 签名：普通 MD5 摘要（非 HMAC）
    public static native String nativeSign(int page, long ts, String enc);

    // 响应解密：**换一把钥**（AES-128-CBC，iv 前置）
    public static native String nativeDecryptRsp(String hexData);

    // 本地提交比对值
    public static native String nativeAnswer();

    // 只读自检：只报密码原语、主标记来源与检测评分，不含密钥明文、不判胜
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
        final String enc;
        final String sign;
        try {
            enc = FlutterMirror.nativeEnc(page, ts);
            sign = FlutterMirror.nativeSign(page, ts, enc);
        } catch (Throwable t) {
            cb.onError("参数构造失败");
            return;
        }
        try {
            final OkHttpClient c = trustClient();
            FormBody form = new FormBody.Builder()
                    .add("page", String.valueOf(page))
                    .add("ts", String.valueOf(ts))
                    .add("enc", enc)
                    .add("sign", sign)
                    .build();
            Request req = new Request.Builder()
                    .url(base + "/api/kl40")
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
                            cb.onError("HTTP " + response.code() + ": " + text);
                            return;
                        }
                        // 响应体换了一把钥：先过 so 解密，再解析
                        String plain = FlutterMirror.nativeDecryptRsp(
                                new JSONObject(text).getString("d"));
                        JSONObject obj = new JSONObject(plain);
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
