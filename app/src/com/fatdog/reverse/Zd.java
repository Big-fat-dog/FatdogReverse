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

// TLS 客户端：trust chain 复用内置 CA（Tm.caDer()）；
// sign + enc 由 Wp.nativeSignAndEnc(page, ts) 算，POST 表单提交；
// 响应 {"d": hex(AES(nums))} 用 Wp.nativeDecrypt 解密。
public class Zd {
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
        final String[] parts = Wp.nativeSignAndEnc(page, ts);
        if (parts == null || parts.length < 2) {
            cb.onError("native sign/enc 失败");
            return;
        }
        final String sign = parts[0];
        final String enc = parts[1];
        try {
            final OkHttpClient c = trustClient();
            String url = base + "/api/l47";
            FormBody body = new FormBody.Builder()
                    .add("page", String.valueOf(page))
                    .add("ts", String.valueOf(ts))
                    .add("sign", sign)
                    .add("enc", enc)
                    .build();
            Request req = new Request.Builder()
                    .url(url)
                    .header("User-Agent", "Fatdog/1.0 (Android)")
                    .post(body)
                    .build();
            c.newCall(req).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, java.io.IOException e) {
                    cb.onError(e == null ? "网络错误" : e.getMessage());
                }

                @Override
                public void onResponse(Call call, Response response) {
                    try (ResponseBody rsp = response.body()) {
                        String text = rsp == null ? "" : rsp.string();
                        if (!response.isSuccessful()) {
                            cb.onError("HTTP " + response.code() + ": " + text);
                            return;
                        }
                        JSONObject obj = new JSONObject(text);
                        String hexD = obj.getString("d");
                        String plain = Wp.nativeDecrypt(hexD);
                        if (plain == null || plain.isEmpty()) {
                            cb.onError("解密失败");
                            return;
                        }
                        // plain = "page=N|nums=1,2,3,..."
                        String[] kv = plain.split("\\|", 2);
                        if (kv.length < 2) {
                            cb.onError("响应格式错误: " + plain);
                            return;
                        }
                        String[] numStrs = kv[1].replace("nums=", "").split(",");
                        int[] nums = new int[numStrs.length];
                        for (int i = 0; i < numStrs.length; i++) nums[i] = Integer.parseInt(numStrs[i].trim());
                        int gotPage = Integer.parseInt(kv[0].replace("page=", "").trim());
                        cb.onPage(gotPage, nums);
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
