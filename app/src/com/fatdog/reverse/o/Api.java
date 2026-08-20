package com.fatdog.reverse.o;

import com.fatdog.reverse.NetHost;

import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 19 网络核心：POST 表单，AES 加密参数 + HMAC 签名，响应体 AES 解密。
// 本包会被 R8 混淆成 a/b/c，接口路径/算法名/密钥也全是加密串。
public class Api {
    static final String BASE = NetHost.httpBase();   // 主机自动选择：模拟器 10.0.2.2 / 真机 127.0.0.1

    public static String base() {
        return BASE;
    }

    public interface Cb {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    private static final OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build();

    public static void fetchPage(final String base, final int page, final Cb cb) {
        long ts = System.currentTimeMillis() / 1000;
        String enc = Encrypt.aesEncode("page=" + page + "&ts=" + ts, Keys.aesReqKey());
        String sign = Encrypt.hmacSign(enc, Keys.hmacKey());
        FormBody form = new FormBody.Builder()
                .add("page", String.valueOf(page))
                .add("ts", String.valueOf(ts))
                .add("enc", enc)
                .add("sign", sign)
                .add("client", "android-fatdemo")
                .add("chan", "ctf")
                .add("ver", "1.9")
                .add("dev", "0000000000000000")
                .build();
        Request req = new Request.Builder()
                .url(base + Keys.path())
                .header("User-Agent", "Fatdemo/1.0 (Android)")
                .post(form)
                .build();
        client.newCall(req).enqueue(new Callback() {
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
                    String clear = Encrypt.aesDecode(obj.getString("d"), Keys.aesRspKey());
                    String[] parts = clear.split("\\|");
                    if (parts.length != 2 || !parts[0].startsWith("page=")) {
                        cb.onError("响应解密格式不对");
                        return;
                    }
                    int got = Integer.parseInt(parts[0].substring(5));
                    String[] ns = parts[1].substring(5).split(",");
                    int[] nums = new int[ns.length];
                    for (int i = 0; i < ns.length; i++) {
                        nums[i] = Integer.parseInt(ns[i]);
                    }
                    cb.onPage(got, nums);
                } catch (Exception e) {
                    cb.onError(e == null ? "响应解析失败" : e.getMessage());
                }
            }
        });
    }
}