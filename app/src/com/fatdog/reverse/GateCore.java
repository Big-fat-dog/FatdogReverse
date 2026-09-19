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
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 天地秘境·迷阵 KL55「破阵而出」的 JNI 桥 + 网络助手（OLLVM 综合收官卷）。
// libgate.so 六重叠加：平坦化 + 虚假控制流 + 字符串加密(JNI_OnLoad) + 间接跳转 + 多层嵌套 + 反调试评分制。
// 请求链：enc = hex(魔改AES-128-ECB(S盒换值, aes_key, "page=N&ts=T")), sign = SHA256(真标记+"|"+page+"|"+ts)。
// 响应体：魔改Base64(魔改AES-128-CBC(resp_key, resp_iv, JSON))，需还原自定义码表 b64decode 再魔改 AES 解密。
public class GateCore {
    static {
        System.loadLibrary("gate");
    }

    private GateCore() {
    }

    // 综合签名：间接跳转派发到真实签名（内部走平坦化），返回 enc hex
    public static native String nativeSign(int page, long ts);

    // 返回 sign hex（SHA256 摘要链）
    public static native String nativeSignHex(int page, long ts);

    // 解密响应体：魔改 Base64 解码 + 魔改 AES-CBC 解密，返回明文 JSON 字符串
    public static native String nativeDecrypt(String b64);

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
        final String enc = GateCore.nativeSign(page, ts);
        final String sign = GateCore.nativeSignHex(page, ts);
        try {
            final OkHttpClient c = trustClient();
            String url = base + "/api/kl55";
            MediaType mime = MediaType.parse("application/x-www-form-urlencoded");
            String form = "page=" + page + "&ts=" + ts + "&enc=" + enc + "&sign=" + sign;
            RequestBody body = RequestBody.create(mime, form);
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
                    try (ResponseBody rb = response.body()) {
                        String raw = rb == null ? "" : rb.string();
                        if (!response.isSuccessful()) {
                            cb.onError("HTTP " + response.code() + ": " + raw);
                            return;
                        }
                        // 响应体是魔改 Base64(魔改 AES-CBC)，交给 native 解密
                        String plain = GateCore.nativeDecrypt(raw.trim());
                        if (plain == null || plain.isEmpty()) {
                            cb.onError("响应体无法解密");
                            return;
                        }
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
