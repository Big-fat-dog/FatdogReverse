package com.fatdog.reverse;

import org.json.JSONObject;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

// 关卡 16 的网络核心：请求参数用 RC4 加密、MD5 签名；响应体用另一把 RC4 密钥解密。
// 三把密钥素材都是"Jk 前缀 + 本类后缀"运行时拼出来的，dex 里不存在完整密钥字符串。
// 与 L15（Sg）的区别：L15 只有 HMAC 签名、响应明文；L16 请求和响应都是密文。
public class C16 {
    static final String BASE = NetHost.httpBase();   // 主机自动选择：模拟器 10.0.2.2 / 真机 127.0.0.1

    /** 页面数据回调：跑在 OkHttp 工作线程，调用方要自己切回主线程刷 UI。 */
    public interface PageCallback {
        void onPage(int page, int[] nums);
        void onError(String msg);
    }

    // 三串"废字节"：与 Jk 的前缀拼起来才是完整密钥/盐。
    static final byte[] K1B = {78, 89, 77, 99, 14, 12, 14, 10};      // ^0x3C
    static final byte[] K2B = {35, 34, 33, 14, 99, 97, 99, 103};     // ^0x51
    static final byte[] SB = {99, 79, 85, 91, 99, 79, 93, 80, 72};   // ^0x3C

    static byte[] buildReqKey() {
        return concat(Jk.reqPrefix().getBytes(), decode(K1B, 0x3C));
    }

    static byte[] buildRspKey() {
        return concat(Jk.rspPrefix().getBytes(), decode(K2B, 0x51));
    }

    static String buildSigSecret() {
        return Jk.sigPrefix() + new String(decode(SB, 0x3C));
    }

    private static byte[] decode(byte[] in, int x) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ x);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static String md5Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /** 全局单例：连接池/线程池复用，主流 App 都是这么写。 */
    private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build();

    /**
     * 异步取一页：
     *   plain   = "page=N&ts=T"
     *   payload = hex( RC4(reqKey, plain) )
     *   sig     = md5( payload + sigSecret )
     *   url     = /api/rc4?payload=...&sig=...
     *   响应 JSON {"d": hex( RC4(rspKey, "page=N|nums=a,b,...") )}，本地解密后回调。
     */
    static void fetchPage(String base, final int page, final PageCallback cb) {
        long ts = System.currentTimeMillis() / 1000;
        String plain = "page=" + page + "&ts=" + ts;
        String payload = Rc4Core.hex(Rc4Core.crypt(plain.getBytes(), buildReqKey()));
        String sig = md5Hex(payload + buildSigSecret());
        String url = base + "/api/rc4?payload=" + payload + "&sig=" + sig;

        Request req = new Request.Builder()
                .url(url)
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
                    byte[] clear = Rc4Core.crypt(
                            Rc4Core.unhex(obj.getString("d")), buildRspKey());
                    String[] parts = new String(clear, "UTF-8").split("\\|");
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
