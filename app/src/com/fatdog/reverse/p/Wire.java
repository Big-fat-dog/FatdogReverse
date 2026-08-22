package com.fatdog.reverse.p;

import org.json.JSONObject;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 27 网络核心：POST 表单，AES 加密参数 + HMAC 签名，响应体 AES 解密；
// TLS 走 Gate 的双闸门（TrustManager + CertificatePinner）。本包会被 R8 混淆。
public class Wire {

    public interface Cb {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    public static void fetchPage(final String base, final int page, final Cb cb) {
        OkHttpClient c;
        try {
            c = Gate.get();
        } catch (Exception e) {
            cb.onError(e == null ? "TLS 初始化失败" : e.getMessage());
            return;
        }
        long ts = System.currentTimeMillis() / 1000;
        String enc = Cpt.aesEncode("page=" + page + "&ts=" + ts, Tail.aesReqKey());
        String sign = Cpt.hmacSign(enc, Tail.hmacKey());
        FormBody form = new FormBody.Builder()
                .add("page", String.valueOf(page))
                .add("ts", String.valueOf(ts))
                .add("enc", enc)
                .add("sign", sign)
                .add("client", "android-fatdemo")
                .add("chan", "final")
                .add("ver", "2.7")
                .add("dev", "0000000000000000")
                .build();
        Request req = new Request.Builder()
                .url(base + Mk.path())
                .header("User-Agent", "Fatdemo/1.0 (Android)")
                .post(form)
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
                    String clear = Cpt.aesDecode(obj.getString("d"), Tail.aesRspKey());
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
