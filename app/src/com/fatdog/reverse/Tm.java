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
    static final int[] CAA = {
		106, 216, 88, 189, 106, 216, 91, 149, 250, 89, 88, 91, 88, 88,
		78, 125, 242, 25, 153, 154, 137, 226, 188, 70, 203, 140, 80, 186,
		213, 150, 231, 82, 122, 253, 218, 106, 87, 92, 83, 112, 220, 18,
		220, 173, 87, 91, 91, 81, 95, 90, 106, 121, 107, 123, 106, 69,
		92, 89, 15, 94, 89, 86, 66, 178, 217, 204, 189, 209, 205, 122,
		28, 59, 46, 62, 63, 55, 53, 122, 188, 239, 209, 178, 245, 207,
		122, 25, 27, 106, 68, 77, 87, 104, 108, 106, 98, 104, 106, 107,
		105, 111, 108, 105, 105, 0, 77, 87, 105, 108, 106, 98, 107, 98,
		107, 105, 111, 108, 105, 105, 0, 106, 121, 107, 123, 106, 69, 92,
		89, 15, 94, 89, 86, 66, 178, 217, 204, 189, 209, 205, 122, 28,
		59, 46, 62, 63, 55, 53, 122, 188, 239, 209, 178, 245, 207, 122,
		25, 27, 106, 216, 91, 120, 106, 87, 92, 83, 112, 220, 18, 220,
		173, 87, 91, 91, 91, 95, 90, 89, 216, 91, 85, 90, 106, 216,
		91, 80, 88, 216, 91, 91, 90, 150, 103, 78, 102, 56, 221, 241,
		179, 109, 127, 8, 193, 67, 234, 227, 216, 18, 108, 211, 115, 81,
		62, 6, 181, 173, 238, 240, 229, 210, 144, 10, 221, 253, 128, 176,
		49, 57, 239, 207, 15, 12, 0, 211, 43, 130, 189, 104, 42, 9,
		253, 130, 187, 181, 252, 199, 110, 127, 215, 137, 233, 59, 120, 28,
		131, 198, 51, 62, 86, 208, 155, 233, 10, 19, 186, 176, 173, 201,
		4, 172, 171, 22, 97, 145, 54, 0, 244, 216, 95, 63, 164, 6,
		131, 41, 224, 254, 60, 165, 20, 3, 208, 49, 187, 240, 96, 13,
		18, 59, 199, 83, 174, 131, 102, 180, 158, 9, 42, 237, 125, 165,
		21, 122, 172, 93, 242, 36, 6, 60, 165, 94, 36, 2, 109, 242,
		76, 213, 7, 127, 171, 235, 184, 95, 103, 69, 143, 24, 252, 177,
		159, 169, 57, 144, 85, 150, 98, 146, 43, 210, 234, 73, 232, 36,
		188, 189, 157, 75, 176, 233, 153, 85, 24, 250, 135, 60, 127, 201,
		155, 43, 247, 144, 18, 179, 171, 14, 51, 131, 125, 149, 234, 107,
		104, 117, 43, 67, 1, 103, 223, 30, 235, 29, 49, 102, 140, 137,
		221, 112, 168, 140, 136, 150, 43, 105, 170, 7, 182, 63, 195, 84,
		194, 222, 7, 155, 212, 89, 194, 239, 68, 245, 71, 148, 139, 148,
		249, 68, 179, 137, 218, 71, 2, 20, 70, 57, 174, 227, 221, 30,
		134, 85, 254, 240, 230, 155, 57, 39, 27, 92, 5, 88, 89, 91,
		90, 91, 249, 73, 106, 75, 106, 85, 92, 89, 15, 71, 73, 91,
		91, 165, 94, 95, 106, 89, 91, 91, 165, 106, 87, 92, 83, 112,
		220, 18, 220, 173, 87, 91, 91, 81, 95, 90, 89, 216, 91, 91,
		90, 73, 109, 145, 70, 2, 97, 68, 126, 225, 71, 139, 102, 115,
		163, 91, 103, 9, 208, 147, 26, 15, 86, 12, 175, 224, 137, 245,
		222, 127, 65, 75, 180, 73, 138, 41, 18, 6, 22, 213, 154, 120,
		175, 84, 91, 165, 50, 254, 230, 52, 217, 124, 208, 198, 185, 254,
		224, 113, 92, 208, 179, 47, 14, 92, 233, 59, 67, 143, 47, 230,
		49, 151, 72, 148, 224, 222, 31, 108, 243, 61, 135, 47, 125, 127,
		203, 149, 45, 68, 226, 151, 20, 176, 194, 139, 151, 18, 129, 170,
		43, 188, 11, 70, 185, 255, 45, 210, 44, 255, 141, 24, 242, 106,
		109, 66, 180, 255, 134, 199, 122, 26, 232, 154, 45, 67, 244, 2,
		17, 71, 90, 23, 55, 194, 57, 85, 229, 43, 203, 8, 91, 123,
		74, 32, 112, 190, 125, 100, 96, 7, 117, 10, 153, 146, 74, 38,
		25, 13, 83, 58, 44, 231, 248, 154, 210, 197, 74, 213, 107, 216,
		178, 230, 233, 58, 8, 126, 113, 191, 149, 232, 171, 151, 190, 96,
		94, 172, 50, 139, 63, 29, 223, 231, 80, 91, 17, 99, 226, 59,
		61, 193, 71, 153, 209, 23, 127, 157, 180, 61, 211, 170, 36, 99,
		226, 239, 83, 39, 59, 196, 201, 18, 105, 127, 18, 189, 221, 21,
		252, 104, 226, 24, 104, 24, 121, 33, 244, 75, 229, 91, 220, 19,
		241, 2, 108, 80, 116, 131, 22, 107, 71, 253, 178, 53, 164, 18,
		110, 76, 136, 77, 28
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