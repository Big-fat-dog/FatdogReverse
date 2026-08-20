package com.fatdog.reverse;

import org.json.JSONObject;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 17 的网络核心：POST 表单，参数一大堆，但只有 enc/sig/ts/dog 是有意义的。
//   enc = hex( SM4(req_key, "page=N&ts=T") )      国密对称加密（手写 Sm4Core）
//   sig = SM3( enc + salt )                       国密摘要（手写 Sm3Core）
//   dog = "fatdog"                                固定参数，服务端校验
// 其余 client/chan/ver/dev 只是携带的干扰参数。响应体也是 SM4 密文，要先解密才能渲染。
public class Fl {
    static final String BASE = NetHost.httpBase();   // 主机自动选择：模拟器 10.0.2.2 / 真机 127.0.0.1

    public interface PageCallback {
        void onPage(int page, int[] nums);

        void onError(String msg);
    }

    // 后半段素材（与 Kt 的前半段拼起来）：key/key/salt/dog
    static final byte[] KB = {87, 89, 69};       // ^0x3C -> key
    static final byte[] KC = {58, 52, 40};       // ^0x51 -> key
    static final byte[] SD = {24, 10, 7, 31};    // ^0x6B -> salt
    static final byte[] DB = {25, 18, 26};       // ^0x7D -> dog

    static String buildReqKey() {
        return Kt.reqPrefix() + new String(dec(KB, 0x3C));
    }

    static String buildRspKey() {
        return Kt.rspPrefix() + new String(dec(KC, 0x51));
    }

    static String buildSigSalt() {
        return Kt.saltPrefix() + new String(dec(SD, 0x6B));
    }

    static String dog() {
        return Kt.dogA() + new String(dec(DB, 0x7D));
    }

    private static byte[] dec(byte[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return out;
    }

    private static final SecureRandom RNG = new SecureRandom();
    private static String randomDev() {
        byte[] b = new byte[8];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }

    private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build();

    static void fetchPage(String base, final int page, final PageCallback cb) {
        long ts = System.currentTimeMillis() / 1000;
        String enc = Sm4Core.encryptHex("page=" + page + "&ts=" + ts, buildReqKey());
        String sig = Sm3Core.sm3Hex(enc + buildSigSalt());

        FormBody form = new FormBody.Builder()
                .add("page", String.valueOf(page))
                .add("ts", String.valueOf(ts))
                .add("dog", dog())
                .add("enc", enc)
                .add("sig", sig)
                .add("client", "android-fatdemo")
                .add("chan", "ctf")
                .add("ver", "1.7")
                .add("dev", randomDev())
                .build();

        Request req = new Request.Builder()
                .url(base + "/api/form")
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
                    String clear = Sm4Core.decryptStr(obj.getString("d"), buildRspKey());
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
}