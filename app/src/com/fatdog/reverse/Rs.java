package com.fatdog.reverse;

import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 18 的网络核心：RSA 加密请求参数（标准库 javax.crypto）+ DES 解密响应。
//   enc = base64hex( RSA_encrypt(pub, "page=N&ts=T") )   公钥模数藏在 Pk（异或数组）
//   DES 密钥 = 服务端 /api/dskey 下发的半段 + Pk 里藏的另一半
// 差异点：这关的加密用标准库（RSA/ECB/PKCS1Padding、DES/ECB/PKCS5Padding），不像 L17 手写国密。
public class Rs {
    static final String BASE = NetHost.httpBase();   // 主机自动选择：模拟器 10.0.2.2 / 真机 127.0.0.1

    public interface PageCallback {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    public interface InitCallback {
        void onReady();

        void onError(String msg);
    }

    private static byte[] desKey;

    private static final String DEV_VALUE = "0000000000000000";

    private static PublicKey rsaPublicKey;

    static {
        try {
            rsaPublicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(Pk.modulus(), Pk.exp()));
        } catch (Exception ignored) {
        }
    }

    private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build();

    /** 第一步：向服务端要 DES 密钥的前半段，加上 Pk 里的后半段拼成完整 DES 密钥。 */
    static void init(String base, final InitCallback cb) {
        Request req = new Request.Builder()
                .url(base + "/api/dskey")
                .header("User-Agent", "Fatdemo/1.0 (Android)")
                .get()
                .build();
        CLIENT.newCall(req).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
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
                    byte[] halfA = unhex(obj.getString("k"));
                    byte[] halfB = Pk.desHalfB();
                    desKey = new byte[halfA.length + halfB.length];
                    System.arraycopy(halfA, 0, desKey, 0, halfA.length);
                    System.arraycopy(halfB, 0, desKey, halfA.length, halfB.length);
                    cb.onReady();
                } catch (Exception e) {
                    cb.onError(e == null ? "密钥获取失败" : e.getMessage());
                }
            }
        });
    }

    static void fetchPage(String base, final int page, final PageCallback cb) {
        if (desKey == null) {
            cb.onError("密钥未初始化");
            return;
        }
        long ts = System.currentTimeMillis() / 1000;
        String enc = rsaEncHex("page=" + page + "&ts=" + ts);

        FormBody form = new FormBody.Builder()
                .add("page", String.valueOf(page))
                .add("ts", String.valueOf(ts))
                .add("enc", enc)
                .add("client", "android-fatdemo")
                .add("chan", "ctf")
                .add("ver", "1.8")
                .add("dev", DEV_VALUE)
                .build();

        Request req = new Request.Builder()
                .url(base + "/api/rsa")
                .header("User-Agent", "Fatdemo/1.0 (Android)")
                .post(form)
                .build();

        CLIENT.newCall(req).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
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
                    String clear = desDecryptStr(obj.getString("d"));
                    String[] parts = clear.split("\\|");
                    if (parts.length != 2 || !parts[0].startsWith("page=")) {
                        cb.onError("响应解密格式不对");
                        return;
                    }
                    int got = Integer.parseInt(parts[0].substring(5));
                    String[] numStrs = parts[1].substring(5).split(",");
                    int[] nums = new int[numStrs.length];
                    for (int i = 0; i < numStrs.length; i++) {
                        nums[i] = Integer.parseInt(numStrs[i]);
                    }
                    cb.onPage(got, nums);
                } catch (Exception e) {
                    cb.onError(e == null ? "响应解析失败" : e.getMessage());
                }
            }
        });
    }

    static String rsaEncHex(String plain) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
            return hex(c.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "";
        }
    }

    static String desDecryptStr(String hexCipher) {
        try {
            byte[] ct = unhex(hexCipher);
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(desKey, "DES"));
            return new String(c.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) {
            sb.append(String.format("%02x", v & 0xff));
        }
        return sb.toString();
    }

    static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}