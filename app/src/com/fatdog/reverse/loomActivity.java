package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

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

/**
 * 天机阁 KL30 天机织锦（Protobuf 二进制协议）
 * libloom.so 导出：
 *   byte[] nativeBuildRequest(int page, long ts)  — 编码 PageRequest
 *   boolean nativeVerifyResponse(byte[] data)     — 验证响应
 *   int[]    nativeParseNums(byte[] data)          — 提取 nums
 *   String   nativeAnswer()                        — 最终答案
 *
 * 破解路线：抓包 hex → protoc --decode_raw → 重建 .proto → Python 复刻
 * Flag: FLAG_18_KL30{heavenly_loom}
 */
public class loomActivity extends Activity {

    private static final int PAGES = 100;
    private static final MediaType PROTO = MediaType.parse("application/protobuf");

    private OkHttpClient client;
    private String base;
    private boolean loading;
    private int currentPage = 1;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        base = NetHost.httpsBase();
        initClient();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL30 · 天机织锦（★★ Protobuf 二进制协议）\n\n"
                + "libloom.so 导出四个函数：\n"
                + "  byte[] nativeBuildRequest(page, ts)\n"
                + "  boolean nativeVerifyResponse(data)\n"
                + "  int[]   nativeParseNums(data)\n"
                + "  String  nativeAnswer()\n\n"
                + "请求/响应均为 Protobuf 编码\n"
                + "标记：两个标记一真一假，需仔细辨别");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        statusTv = new TextView(this);
        statusTv.setText("点击「取数」加载第 1 页");
        statusTv.setTextColor(Color.LTGRAY);
        statusTv.setTypeface(Typeface.MONOSPACE);
        statusTv.setTextSize(12);
        statusTv.setGravity(Gravity.CENTER);
        root.addView(statusTv, Ui.fullWidth(6));

        dataTv = new TextView(this);
        dataTv.setTypeface(Typeface.MONOSPACE);
        dataTv.setTextSize(13);
        dataTv.setTextColor(Color.WHITE);
        dataTv.setPadding(Ui.dp(8), Ui.dp(8), Ui.dp(8), Ui.dp(8));
        root.addView(dataTv, Ui.fullWidth(8));

        /* 导航按钮 */
        navBar = new LinearLayout(this);
        navBar.setOrientation(LinearLayout.HORIZONTAL);
        navBar.setGravity(Gravity.CENTER);
        root.addView(navBar, Ui.wrap(6));

        Button fetchBtn = new Button(this);
        fetchBtn.setText("取数"); Ui.styleButton(fetchBtn);
        fetchBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { loadPage(currentPage); }
        });
        root.addView(fetchBtn, Ui.wrap(10));

        EditText pageIn = new EditText(this);
        pageIn.setHint("页码 1-" + PAGES);
        pageIn.setTextColor(Color.WHITE);
        pageIn.setTypeface(Typeface.MONOSPACE);
        pageIn.setBackgroundColor(0x33FFFFFF);
        int p = Ui.dp(10);
        pageIn.setPadding(p, p, p, p);
        root.addView(pageIn, Ui.fullWidth(10));
        pageInput = pageIn;

        Button goBtn = new Button(this);
        goBtn.setText("跳转"); Ui.styleButton(goBtn);
        goBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String s = pageInput.getText().toString().trim();
                if (s.isEmpty()) return;
                int pg = Integer.parseInt(s);
                if (pg >= 1 && pg <= PAGES) { currentPage = pg; loadPage(pg); }
            }
        });
        root.addView(goBtn, Ui.wrap(10));

        EditText ansIn = new EditText(this);
        ansIn.setHint("输入答案（32位 hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        ansIn.setPadding(p, p, p, p);
        root.addView(ansIn, Ui.fullWidth(10));
        ansInput = ansIn;

        Button subBtn = new Button(this);
        subBtn.setText("提交答案"); Ui.styleButton(subBtn);
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansInput.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(loomActivity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Ck.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(loomActivity.this, "FLAG_18_KL30{heavenly_loom}");
                    PassLog.mark(loomActivity.this, "KL30");
                } else {
                    Toast.makeText(loomActivity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(loomActivity.this)
                        .setTitle("提示")
                        .setMessage("Protobuf 二进制协议：\n\n"
                                + "请求 = PageRequest { page: uint32 = 1; ts: uint64 = 2; }\n"
                                + "响应 = PageResponse { code: uint32 = 1; nums: repeated int32 = 2; sign: bytes = 3; }\n\n"
                                + "抓包拿到 hex → protoc --decode_raw 还原结构\n"
                                + "对照字段编号重建 .proto → Python 复刻\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl30, 140));

        setContentView(root);
        ThemeKit.apply(this);
    }

    /* ---------- UI 引用 ---------- */
    private TextView statusTv;
    private TextView dataTv;
    private LinearLayout navBar;
    private EditText pageInput;
    private EditText ansInput;

    /* ---------- TLS ---------- */
    private void initClient() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate ca = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(Tm.caDer()));
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("fatdog", ca);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tmf.getTrustManagers(), new SecureRandom());

            HostnameVerifier hv = new HostnameVerifier() {
                @Override public boolean verify(String hostname, SSLSession session) { return true; }
            };

            client = new OkHttpClient.Builder()
                    .sslSocketFactory(sc.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0])
                    .hostnameVerifier(hv)
                    .connectTimeout(8, TimeUnit.SECONDS)
                    .readTimeout(8, TimeUnit.SECONDS)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /* ---------- 取数 ---------- */
    private void loadPage(final int page) {
        if (loading) return;
        loading = true;
        statusTv.setText("正在请求第 " + page + " 页…");

        final long ts = System.currentTimeMillis() / 1000;
        byte[] reqBytes = Ck.nativeBuildRequest(page, ts);
        RequestBody body = RequestBody.create(PROTO, reqBytes);
        String url = base + "/api/kl30";
        Request req = new Request.Builder().url(url).post(body).build();

        client.newCall(req).enqueue(new Callback() {
            @Override public void onFailure(Call call, java.io.IOException e) {
                loading = false;
                runOnUiThread(new Runnable() {
                    @Override public void run() { statusTv.setText("请求失败: " + e.getMessage()); }
                });
            }
            @Override public void onResponse(Call call, Response rsp) {
                try {
                    if (!rsp.isSuccessful()) {
                        final String msg = "HTTP " + rsp.code();
                        loading = false;
                        runOnUiThread(new Runnable() {
                            @Override public void run() { statusTv.setText(msg); }
                        });
                        return;
                    }
                    byte[] rspBytes = rsp.body().bytes();
                    final boolean ok = Ck.nativeVerifyResponse(rspBytes);
                    final int[] nums = Ck.nativeParseNums(rspBytes);
                    loading = false;
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            currentPage = page;
                            if (ok && nums.length > 0) {
                                StringBuilder sb = new StringBuilder();
                                for (int i = 0; i < nums.length; i++) {
                                    if (i > 0) sb.append(", ");
                                    sb.append(nums[i]);
                                }
                                dataTv.setText("第 " + page + " 页 (" + nums.length + " 个):\n" + sb.toString());
                                statusTv.setText("已加载第 " + page + " / " + PAGES + " 页 ✔");
                            } else {
                                statusTv.setText("响应验证失败");
                            }
                            renderNav();
                        }
                    });
                } catch (Exception e) {
                    loading = false;
                    runOnUiThread(new Runnable() {
                        @Override public void run() { statusTv.setText("解析失败: " + e.getMessage()); }
                    });
                }
            }
        });
    }

    private void renderNav() {
        navBar.removeAllViews();
        if (currentPage > 1) {
            Button prev = new Button(this);
            prev.setText("◀ 上一页"); Ui.styleButton(prev);
            prev.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) { loadPage(currentPage - 1); }
            });
            navBar.addView(prev);
        }
        if (currentPage < PAGES) {
            Button next = new Button(this);
            next.setText("下一页 ▶"); Ui.styleButton(next);
            next.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) { loadPage(currentPage + 1); }
            });
            navBar.addView(next);
        }
    }
}
