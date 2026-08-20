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
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 22 的 TLS 客户端：自定义 TrustManager（信内置 CA，复用 Tm.caDer()）之上，
// 再叠一层 OkHttp CertificatePinner，把服务器证书的 SPKI 焊死（pin 是明文字符串 sha256/...）。
// 于是 mitmproxy 换证书后：TrustManager 那关过不去；就算 Hook 掉它，CertificatePinner 也过不去——双闸门。
// 请求走 HTTPS:8443 的 /api/pin，带 HMAC 签名（密钥前半段 Kp，后半段 "pin_key" 在这里）。
public class Pn {
    static final String BASE = NetHost.httpsBase();   // 主机自动选择：模拟器 10.0.2.2 / 真机 127.0.0.1

    public interface Cb {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    // 服务器证书的 SPKI pin（OkHttp 的 CertificatePinner 默认格式）
    static final String PIN = "sha256/Tix1uqOheqbTST96K/CXQMt79TFjVZprnaUbMo3jv3E=";

    // HMAC 密钥后半段 "pin_key"（^0x3C）
    static final int[] KB = {76, 85, 82, 99, 87, 89, 69};

    private static OkHttpClient client;

    static String buildKey() {
        return Kp.partA() + new String(dec(KB, 0x3C));
    }

    static String sign(int page, long ts) {
        return Kp.hmacSha256Hex(buildKey(), "page=" + page + "&ts=" + ts);
    }

    private static byte[] dec(int[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return out;
    }

    private static synchronized OkHttpClient pinnedClient() throws Exception {
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

        HostnameVerifier hv = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return hostname != null && (hostname.equals("10.0.2.2")
                        || hostname.equals("127.0.0.1") || hostname.equals("localhost"));
            }
        };
        CertificatePinner pinner = new CertificatePinner.Builder()
                .add("10.0.2.2", PIN)
                .add("127.0.0.1", PIN)
                .add("localhost", PIN)
                .build();

        client = new OkHttpClient.Builder()
                .sslSocketFactory(sc.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0])
                .hostnameVerifier(hv)
                .certificatePinner(pinner)
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
        return client;
    }

    static void fetchPage(String base, final int page, final Cb cb) {
        try {
            final OkHttpClient c = pinnedClient();
            long ts = System.currentTimeMillis() / 1000;
            String url = base + "/api/pin?page=" + page + "&ts=" + ts + "&sign=" + sign(page, ts);
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