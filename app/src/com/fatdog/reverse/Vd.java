package com.fatdog.reverse;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 26 的 TLS 客户端：双向认证（mTLS）。
// 信任侧沿用内置 CA（Tm.caDer()）；出示侧由 Mc 打开 assets/mt_client.p12 产出 KeyManager，
// 握手时把客户端证书链交给服务端验证 —— 少一张证书，TLS 都握不上手，抓包工具直接被拒。
// 端点 https://…:8444/api/mtls（NetHost.mtlsBase），HMAC 密钥 = Zt.pa() + 本类 kb()。
public class Vd {
    static final String BASE = NetHost.mtlsBase();

    public interface Cb {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    // HMAC 密钥后半段 "mtls_key"（^0x3C）
    static final int[] KB = {81, 72, 80, 79, 99, 87, 89, 69};

    static String kb() {
        byte[] out = new byte[KB.length];
        for (int i = 0; i < KB.length; i++) {
            out[i] = (byte) (KB[i] ^ 0x3C);
        }
        return new String(out);
    }

    static String buildKey() {
        return Zt.pa() + kb();
    }

    static String sign(int page, long ts) {
        return Zt.hmacSha256Hex(buildKey(), "page=" + page + "&ts=" + ts);
    }

    private static OkHttpClient client;

    private static synchronized OkHttpClient mtlsClient(android.content.Context ctx) throws Exception {
        if (client != null) {
            return client;
        }

        // 信任侧：只信内置自签 CA
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ca = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(Tm.caDer()));
        KeyStore tks = KeyStore.getInstance(KeyStore.getDefaultType());
        tks.load(null, null);
        tks.setCertificateEntry("fatdemo", ca);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(tks);

        // 出示侧：PKCS12 里的客户端证书+私钥
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(Mc.loadP12(ctx.getAssets().open(Mc.P12)), Mc.buildPassword().toCharArray());

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        client = new OkHttpClient.Builder()
                .sslSocketFactory(sc.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0])
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
        return client;
    }

    static void fetchPage(final android.content.Context ctx, String base, final int page, final Cb cb) {
        try {
            final OkHttpClient c = mtlsClient(ctx);
            long ts = System.currentTimeMillis() / 1000;
            String url = base + "/api/mtls?page=" + page + "&ts=" + ts + "&sign=" + sign(page, ts);
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
            cb.onError(e == null ? "mTLS 初始化失败" : e.getMessage());
        }
    }
}
