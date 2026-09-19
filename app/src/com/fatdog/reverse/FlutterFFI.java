package com.fatdog.reverse;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
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

// 碧落天 KL39「月下独酌」的 JNI 桥 + 网络助手。
// 摘要由 Dart 侧算（此处由 Java 侧代算，模拟跨边界传值），对称加密在 native 侧完成；
// 密钥被掰成两瓣，一瓣在载荷、一瓣在 native，运行时才拼回。
public class FlutterFFI {
    static {
        System.loadLibrary("bow");
    }

    private FlutterFFI() {
    }

    // 加密：enc = AES-128-ECB-PKCS7(两瓣拼回的密钥, <dHex 的 16 字节>)
    // dHex 为 null/空时，native 自行计算摘要（等价于 Dart 侧那条 fd_moon_enc 路径）
    public static native String nativeEnc(int page, long ts, String dHex);

    // 本地提交比对值
    public static native String nativeAnswer();

    // 只读自检：只报密码原语与两瓣来源，不含密钥明文、不判胜
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

    /** 摘要侧那一半：MD5("page=N&ts=T") 的 16 字节 hex（Dart 侧同一份口径）。 */
    static String md5Of(int page, long ts) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] d = md.digest(("page=" + page + "&ts=" + ts).getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    static void fetchPage(String base, final int page, final Cb cb) {
        final long ts = System.currentTimeMillis() / 1000;
        final String enc;
        try {
            enc = FlutterFFI.nativeEnc(page, ts, md5Of(page, ts));
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
                    .build();
            Request req = new Request.Builder()
                    .url(base + "/api/kl39")
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
