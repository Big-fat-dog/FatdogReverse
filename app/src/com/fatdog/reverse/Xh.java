package com.fatdog.reverse;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
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

// TLS 客户端：信任链复用内置 CA（Tm.caDer()）；HMAC 密钥后半在本类，
// 前半在 Wk；签名校验本身已全部下沉 libpearl.so。
//
// 2026-10-02 双层链路：取数前先向 libpearl.so 要一次性令牌 vt（门不开则拿不到 → 不发包）；
// 再用「② 校验结论」挑标记——通过用真标记，异常用诱饵标记（服务端据此回脏数据）。
public class Xh {
    static final String BASE = NetHost.httpsBase();

    // 信任基准后半（^0x5A 还原）
    static final int[] PB = {
            63,63,60,105,109,108,111,63,63,62,98,98,105,104,99,104,
            99,107,108,98,57,59,106,63,104,104,107,104,105,109,60,63,
    };

    // HMAC 密钥后半（^0x5A 还原）
    static final int[] KB = {    60,53,40,61,63,};

static String decode(int[] arr, int k) {
        StringBuilder sb = new StringBuilder(arr.length);
        for (int v : arr) sb.append((char) (v ^ k));
        return sb.toString();
    }

    static String hmacHex(String key, String msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(
                    key.getBytes("UTF-8"), "HmacSHA256"));
            byte[] d = mac.doFinal(msg.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    static String sha256Of(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest(s.getBytes("UTF-8"))) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 取数签名：key = SHA256(标记 ‖ vt)，sign = HMAC-SHA256(key, "page=N&ts=T")。
     * ② 校验通过（auditCode==0）→ 真标记；否则 → 诱饵标记（服务端据此回脏数据）。
     */
    static String signFor(int page, long ts, String vt) {
        String marker = (Wk.auditCode() == 0) ? Wk.hmacKey() : Yk.FAKE_KEY;
        return hmacHex(sha256Of(marker + "|" + vt), "page=" + page + "&ts=" + ts);
    }

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

    static void fetchPage(String base, final int page, final String vt, final Cb cb) {
        final long ts = System.currentTimeMillis() / 1000;
        final String sign = signFor(page, ts, vt);
        try {
            final OkHttpClient c = trustClient();
            String url = base + "/api/l44?page=" + page + "&ts=" + ts
                    + "&vt=" + vt + "&sign=" + sign;
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
                        org.json.JSONArray arr = obj.getJSONArray("nums");
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
