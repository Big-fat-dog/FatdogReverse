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

// 关卡 31 的发包器：每次翻页连发四个请求——1 个真包 + 3 个干扰包，
// 字段名完全一致、形态一模一样，只有响应内容分得出真假：
//   错位包（载荷与表单页号不一致）、废签包（签名是摆设）、噪声包（enc 全零）。
// 假包要么 403 要么返回"形似而空"的 {page, nums:[]}。
public class Xd {
    static final String BASE = NetHost.httpsBase();

    public interface Cb {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    private static final String FAKE_SIGN =
            "deadbeefcafebabe0123456789abcdefdeadbeefcafebabe0123456789abcdef";
    private static final int PACKETS = 4;

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
        final String enc = Zr.nativeEnc(page, ts);
        final String sign = Zr.nativeSign(enc);

        StringBuilder noise = new StringBuilder();
        for (int i = 0; i < enc.length(); i++) noise.append('0');

        final int[] done = {0};
        final boolean[] got = {false};
        final OkHttpClient c;
        try {
            c = trustClient();
        } catch (Exception e) {
            cb.onError(e == null ? "TLS 初始化失败" : e.getMessage());
            return;
        }

        post(c, base, page, page, ts, enc, sign, done, got, cb);                 // 真包
        post(c, base, page, page + 1, ts, enc, sign, done, got, cb);             // 错位包
        post(c, base, page, page, ts, enc, FAKE_SIGN, done, got, cb);            // 废签包
        post(c, base, page, page, ts, noise.toString(), FAKE_SIGN, done, got, cb); // 噪声包
    }

    private static void post(OkHttpClient c, String base, final int wantPage, final int formPage,
                             final long ts, final String enc, final String sign,
                             final int[] done, final boolean[] got, final Cb cb) {
        FormBody body = new FormBody.Builder()
                .add("page", String.valueOf(formPage))
                .add("ts", String.valueOf(ts))
                .add("enc", enc)
                .add("sign", sign)
                .build();
        Request req = new Request.Builder()
                .url(base + "/api/l31")
                .post(body)
                .header("User-Agent", "Fatdog/1.0 (Android)")
                .build();
        c.newCall(req).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, java.io.IOException e) {
                settle(cb, wantPage, done, got, null);
            }

            @Override
            public void onResponse(Call call, Response response) {
                int[] nums = null;
                try (ResponseBody rb = response.body()) {
                    String text = rb == null ? "" : rb.string();
                    if (response.isSuccessful()) {
                        JSONObject obj = new JSONObject(text);
                        org.json.JSONArray arr = obj.getJSONArray("nums");
                        if (arr.length() > 0) {
                            nums = new int[arr.length()];
                            for (int i = 0; i < arr.length(); i++) nums[i] = arr.getInt(i);
                        }
                    }
                } catch (Exception ignored) {
                }
                settle(cb, wantPage, done, got, nums);
            }
        });
    }

    private static void settle(Cb cb, int wantPage, int[] done, boolean[] got, int[] nums) {
        boolean finish;
        synchronized (done) {
            if (nums != null && !got[0]) {
                got[0] = true;
                cb.onPage(wantPage, nums);
            }
            done[0]++;
            finish = (done[0] >= PACKETS && !got[0]);
        }
        if (finish) cb.onError("网络错误");
    }

}
