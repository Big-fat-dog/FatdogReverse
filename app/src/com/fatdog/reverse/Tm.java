package com.fatdog.reverse;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 21 的 TLS 客户端：自定义 TrustManager，只信内置的自签 CA（证书 DER 以异或数组藏着），
// 别的 CA（比如 mitmproxy 的）一律不信 —— 想抓包就得 Hook 掉这个 TrustManager。
// 请求走 HTTPS:8443 的 /api/tls，带 HMAC 签名（密钥前半段在 Km，后半段 "ssl_hmac" 在这里）。
public class Tm {
    static final String BASE = NetHost.httpsBase();   // 主机自动选择：模拟器 10.0.2.2 / 真机 127.0.0.1

    public interface Cb {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    // 内置自签 CA 的 DER（^0x5A）
    static final int[] CAA = {106, 216, 88, 189, 106, 216, 91, 149, 250, 89, 88, 91, 88, 88,
            78, 117, 211, 201, 154, 210, 220, 225, 121, 129, 188, 62, 169, 199,
            209, 30, 174, 185, 166, 24, 40, 106, 87, 92, 83, 112, 220, 18,
            220, 173, 87, 91, 91, 81, 95, 90, 106, 121, 107, 123, 106, 69,
            92, 89, 15, 94, 89, 86, 66, 178, 217, 204, 189, 209, 205, 122,
            28, 59, 46, 62, 63, 55, 53, 122, 188, 239, 209, 178, 245, 207,
            122, 25, 27, 106, 68, 77, 87, 104, 108, 106, 98, 107, 98, 106,
            98, 110, 104, 106, 110, 0, 77, 87, 105, 108, 106, 98, 107, 108,
            106, 98, 110, 104, 106, 110, 0, 106, 121, 107, 123, 106, 69, 92,
            89, 15, 94, 89, 86, 66, 178, 217, 204, 189, 209, 205, 122, 28,
            59, 46, 62, 63, 55, 53, 122, 188, 239, 209, 178, 245, 207, 122,
            25, 27, 106, 216, 91, 120, 106, 87, 92, 83, 112, 220, 18, 220,
            173, 87, 91, 91, 91, 95, 90, 89, 216, 91, 85, 90, 106, 216,
            91, 80, 88, 216, 91, 91, 90, 198, 227, 14, 164, 25, 225, 231,
            12, 88, 61, 220, 156, 81, 134, 130, 2, 236, 57, 196, 163, 102,
            53, 198, 126, 53, 118, 156, 111, 209, 87, 27, 247, 104, 54, 28,
            206, 29, 253, 253, 72, 200, 166, 44, 91, 205, 231, 135, 71, 100,
            6, 16, 210, 242, 113, 252, 137, 21, 100, 249, 137, 5, 81, 111,
            188, 232, 50, 72, 166, 251, 220, 131, 44, 232, 192, 94, 17, 115,
            83, 38, 146, 255, 238, 91, 63, 116, 201, 42, 171, 189, 9, 119,
            18, 116, 55, 107, 82, 196, 25, 223, 219, 114, 99, 30, 220, 127,
            201, 193, 0, 76, 93, 61, 169, 193, 27, 176, 255, 75, 226, 157,
            174, 187, 95, 151, 243, 112, 151, 110, 197, 47, 252, 200, 228, 127,
            237, 4, 109, 57, 212, 65, 68, 172, 192, 35, 187, 204, 3, 72,
            196, 230, 24, 164, 34, 195, 210, 53, 31, 88, 28, 97, 179, 170,
            141, 1, 47, 1, 207, 223, 116, 159, 18, 0, 81, 154, 188, 63,
            77, 102, 246, 7, 229, 197, 76, 148, 125, 171, 182, 185, 78, 75,
            53, 240, 32, 3, 72, 154, 176, 24, 184, 88, 93, 68, 238, 113,
            26, 251, 8, 21, 215, 249, 13, 119, 44, 78, 155, 241, 115, 165,
            112, 245, 198, 167, 127, 190, 99, 176, 154, 244, 188, 58, 31, 221,
            70, 123, 73, 190, 132, 203, 140, 232, 60, 5, 63, 239, 196, 18,
            24, 164, 177, 60, 35, 184, 62, 87, 186, 28, 75, 88, 89, 91,
            90, 91, 249, 73, 106, 75, 106, 85, 92, 89, 15, 71, 73, 91,
            91, 165, 94, 95, 106, 89, 91, 91, 165, 106, 87, 92, 83, 112,
            220, 18, 220, 173, 87, 91, 91, 81, 95, 90, 89, 216, 91, 91,
            90, 117, 39, 74, 125, 27, 224, 242, 117, 170, 122, 21, 176, 30,
            126, 60, 133, 127, 202, 103, 118, 232, 104, 203, 158, 61, 250, 59,
            74, 174, 238, 68, 45, 102, 247, 37, 115, 24, 58, 220, 152, 167,
            114, 114, 128, 3, 156, 154, 184, 178, 45, 44, 203, 11, 235, 153,
            206, 56, 47, 102, 126, 75, 193, 122, 169, 81, 198, 21, 46, 232,
            206, 141, 219, 54, 119, 249, 214, 80, 38, 60, 117, 233, 145, 170,
            193, 127, 55, 201, 191, 19, 42, 154, 127, 206, 11, 46, 174, 63,
            130, 156, 175, 229, 196, 158, 169, 34, 123, 74, 176, 7, 193, 117,
            140, 56, 133, 128, 193, 5, 134, 247, 150, 110, 254, 132, 75, 176,
            196, 16, 21, 210, 245, 177, 110, 48, 104, 60, 103, 237, 61, 59,
            232, 251, 20, 77, 65, 27, 149, 104, 14, 26, 145, 65, 102, 161,
            52, 87, 140, 23, 253, 181, 14, 243, 119, 182, 62, 42, 22, 113,
            62, 151, 157, 155, 56, 4, 253, 114, 191, 167, 252, 32, 13, 217,
            90, 19, 205, 32, 8, 200, 176, 143, 62, 104, 94, 202, 68, 37,
            245, 255, 40, 171, 113, 239, 212, 130, 207, 71, 207, 254, 171, 96,
            188, 106, 185, 133, 248, 87, 69, 142, 45, 206, 166, 254, 64, 184,
            116, 81, 89, 43, 255, 153, 88, 9, 9, 234, 44, 177, 128, 140,
            172, 220, 62, 61, 74, 17, 62, 81, 44, 193, 194, 237, 24, 163,
            244, 188, 74, 85, 48,
    };
    // HMAC 密钥后半段 "ssl_hmac"（^0x3C）
    static final int[] TB = {79, 79, 80, 99, 84, 81, 93, 95};

    private static OkHttpClient client;

    static String buildKey() {
        return Km.partA() + new String(dec(TB, 0x3C));
    }

    static String sign(int page, long ts) {
        return Km.hmacSha256Hex(buildKey(), "page=" + page + "&ts=" + ts);
    }

    private static byte[] dec(int[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return out;
    }

    /** 关卡 21/22 共用：内置自签 CA 的 DER（L22 的 CertificatePinner 也用它做信任链）。 */
    public static byte[] caDer() {
        return dec(CAA, 0x5A);
    }

    private static synchronized OkHttpClient trustClient() throws Exception {
        if (client != null) {
            return client;
        }
        byte[] der = caDer();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ca = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("fatdemo", ca);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, tmf.getTrustManagers(), new SecureRandom());
        client = new OkHttpClient.Builder()
                .sslSocketFactory(sc.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0])
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
        return client;
    }

    static void fetchPage(String base, final int page, final Cb cb) {
        try {
            final OkHttpClient c = trustClient();
            long ts = System.currentTimeMillis() / 1000;
            String url = base + "/api/tls?page=" + page + "&ts=" + ts + "&sign=" + sign(page, ts);
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