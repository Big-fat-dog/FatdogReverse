package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.drawable.GradientDrawable;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
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
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Native大陆 L53 焚天火域（★★★★★ Feistel + 魔改 AES 双算法 · 3 SO 分离 · 最终关）
 *
 * libnative53.so  — 调度 + 异常控制流
 * libnative53c.so — Feistel + 魔改 AES 双算法 + 密钥
 * libnative53b.so — 22类业务代码干扰（dlopen 加载）
 *
 * 破解路线：
 *   ① IDA 分析 3 个 SO，识别 Feistel 与独立魔改 AES 两条分支
 *   ② 还原魔改 S 盒、FK 异或、密钥扩展和两种轮结构
 *   ③ Frida hook Bk53.nativeSign/nativeEnc 拿明文 payload 对拍
 *   ④ Python 复刻全部加密 + HMAC 签名 + RC4 解密响应
 *
 * Flag: FLAG_18_L53{scorched_fireland}
 */
public class x53Activity extends Activity {

    private static final int PAGES = 100;
    private static final int PER_PAGE = 10;
    private static final String SUM_HASH = "070cf7dceebe34d383de3862873f41afb575201be268d7b36ffb672a301cca35";

    private OkHttpClient client;
    private String base;
    private boolean loading;
    private int currentPage = 1;

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private EditText pageInput;
    private EditText ansInput;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        base = NetHost.httpsBase();
        initClient();

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(14), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("L53 · 焚天火域（★★★★★ Feistel + 魔改 AES 双算法 · 最终关）\n"
                + "libnative53.so  — 调度 + 异常控制流\n"
                + "libnative53c.so — Feistel + 魔改 AES 双算法 + 密钥\n"
                + "libnative53b.so — 22类业务代码干扰\n"
                + "Feistel + 魔改 AES + HMAC-SHA256 + RC4");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        status = new TextView(this);
        status.setText("准备中…");
        status.setGravity(Gravity.CENTER);
        status.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(status, Ui.wrap(8));

        GridLayout grid = new GridLayout(this);
        grid.setColumnCount(5);
        grid.setRowCount(2);
        for (int i = 0; i < 10; i++) {
            TextView c = new TextView(this);
            c.setGravity(Gravity.CENTER);
            c.setTextSize(17);
            c.setTypeface(Typeface.DEFAULT_BOLD);
            c.setTextColor(0xFFECECF2);
            GradientDrawable bg = new GradientDrawable();
            bg.setShape(GradientDrawable.RECTANGLE);
            bg.setCornerRadius(Ui.dp(10));
            bg.setColor(0xFF24242B);
            c.setBackground(bg);
            c.setPadding(0, Ui.dp(8), 0, Ui.dp(8));
            GridLayout.LayoutParams lp = new GridLayout.LayoutParams();
            lp.width = 0;
            lp.height = GridLayout.LayoutParams.WRAP_CONTENT;
            lp.columnSpec = GridLayout.spec(i % 5, 1f);
            lp.rowSpec = GridLayout.spec(i / 5);
            lp.setMargins(Ui.dp(3), Ui.dp(3), Ui.dp(3), Ui.dp(3));
            grid.addView(c, lp);
            cells[i] = c;
        }
        box.addView(grid, Ui.fullWidth(12));

        LinearLayout navRow = new LinearLayout(this);
        navRow.setOrientation(LinearLayout.HORIZONTAL);
        navRow.setGravity(Gravity.CENTER_VERTICAL);

        Button prev = new Button(this);
        prev.setText("◀ 上一页");
        Ui.styleButton(prev);
        navRow.addView(prev, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        prev.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { if (currentPage > 1) loadPage(currentPage - 1); }
        });

        HorizontalScrollView hsv = new HorizontalScrollView(this);
        hsv.setHorizontalScrollBarEnabled(false);
        pageBar = new LinearLayout(this);
        pageBar.setOrientation(LinearLayout.HORIZONTAL);
        hsv.addView(pageBar);
        navRow.addView(hsv, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button next = new Button(this);
        next.setText("下一页 ▶");
        Ui.styleButton(next);
        navRow.addView(next, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        next.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { if (currentPage < PAGES) loadPage(currentPage + 1); }
        });

        box.addView(navRow, Ui.fullWidth(14));

        LinearLayout jumpRow = new LinearLayout(this);
        jumpRow.setOrientation(LinearLayout.HORIZONTAL);
        jumpRow.setGravity(Gravity.CENTER_VERTICAL);
        pageInput = new EditText(this);
        pageInput.setHint("页码 1-" + PAGES);
        pageInput.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        jumpRow.addView(pageInput);
        Button jump = new Button(this);
        jump.setText("跳转");
        Ui.styleButton(jump);
        jumpRow.addView(jump);
        jump.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String s = pageInput.getText().toString().trim();
                try {
                    int p = Integer.parseInt(s);
                    if (p >= 1 && p <= PAGES) loadPage(p);
                    else Toast.makeText(x53Activity.this, "页码超出范围 1-" + PAGES, Toast.LENGTH_SHORT).show();
                } catch (Exception e) { Toast.makeText(x53Activity.this, "请输入页码", Toast.LENGTH_SHORT).show(); }
            }
        });
        box.addView(jumpRow, Ui.fullWidth(10));

        ansInput = new EditText(this);
        ansInput.setHint("输入 1000 个数字的总和");
        ansInput.setLayoutParams(Ui.fullWidth(22));
        box.addView(ansInput);

        Button subBtn = new Button(this);
        subBtn.setText("提交答案");
        Ui.styleButton(subBtn);
        box.addView(subBtn, Ui.wrap(14));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(x53Activity.this)
                        .setTitle("提示")
                        .setMessage("Feistel + 魔改 AES 双算法 + 3 SO 分离：\n\n"
                                + "libnative53c.so 的 algo=1 走 Feistel 轮函数（8轮×3子密钥），algo=2 走独立魔改 AES 分组路径（S盒替换 + ShiftRows + 变体列混合）\n"
                                + "两条分支共用魔改 S 盒、FK 异或和密钥扩展；libnative53.so 里的 try/catch 先对输入做 XOR 掩码\n"
                                + "libnative53b.so 里是 22 类业务代码干扰\n\n"
                                + "Frida 训练：\n"
                                + "  • Hook Bk53.nativeSign / nativeEnc 拿明文 payload\n"
                                + "  • 异常控制流：注意 try/catch 块里藏真逻辑\n"
                                + "  • 响应 RC4 解密：hook nativeRc4Decrypt\n\n"
                                + "Python 复刻：分别复刻 Feistel 与魔改 AES，再做 HMAC 与 RC4 解密响应。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(10));

        box.addView(Ui.banner(this, R.drawable.level_53, 150));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansInput.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(x53Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                if (sha256Hex(ans).equals(SUM_HASH)) {
                    Celebration.show(x53Activity.this, "FLAG_18_L53{scorched_fireland}");
                    PassLog.mark(x53Activity.this, "L53");
                } else {
                    Toast.makeText(x53Activity.this, "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        loadPage(1);
    }

    private void render(int[] nums) {
        for (int i = 0; i < cells.length; i++) {
            if (i < nums.length) { cells[i].setText(String.valueOf(nums[i])); cells[i].setVisibility(View.VISIBLE); }
            else cells[i].setVisibility(View.INVISIBLE);
        }
    }

    private void renderNav() {
        pageBar.removeAllViews();
        int win = 3;
        int start = Math.max(1, currentPage - win);
        int end = Math.min(PAGES, currentPage + win);
        for (int p = start; p <= end; p++) {
            final int fp = p;
            TextView chip = new TextView(this);
            chip.setText(String.valueOf(p));
            chip.setTextSize(14);
            chip.setTypeface(Typeface.DEFAULT_BOLD);
            chip.setGravity(Gravity.CENTER);
            chip.setPadding(Ui.dp(12), Ui.dp(6), Ui.dp(12), Ui.dp(6));
            GradientDrawable g = new GradientDrawable();
            g.setShape(GradientDrawable.RECTANGLE);
            g.setCornerRadius(Ui.dp(14));
            boolean sel = (p == currentPage);
            g.setColor(sel ? 0xFFFB7299 : (ThemeKit.isDark(this) ? 0xFF2A2A33 : 0xFFF1F1F4));
            chip.setBackground(g);
            chip.setTextColor(sel ? 0xFFFFFFFF : (ThemeKit.isDark(this) ? 0xFFD8D8E0 : 0xFF3A3A42));
            chip.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) { if (fp != currentPage) loadPage(fp); }
            });
            pageBar.addView(chip, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        }
    }

    private void initClient() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate ca = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Tm.caDer()));
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("fatdog", ca);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tmf.getTrustManagers(), new SecureRandom());
            HostnameVerifier hv = new HostnameVerifier() { @Override public boolean verify(String h, SSLSession s) { return true; } };
            client = new OkHttpClient.Builder()
                    .sslSocketFactory(sc.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0])
                    .hostnameVerifier(hv)
                    .connectTimeout(8, TimeUnit.SECONDS)
                    .readTimeout(8, TimeUnit.SECONDS)
                    .build();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private void loadPage(final int page) {
        if (loading) return;
        loading = true;
        status.setText("正在请求第 " + page + " 页…");
        final long ts = System.currentTimeMillis() / 1000;
        String payload = "page=" + page + "&ts=" + ts;
        String enc = Bk53.nativeEnc(payload, 1);
        String aes = Bk53.nativeEnc(payload, 2);
        String sign = Bk53.nativeSign(payload);

        RequestBody body = new FormBody.Builder()
                .add("page", String.valueOf(page))
                .add("ts", String.valueOf(ts))
                .add("enc", enc)
                .add("aes", aes)
                .add("sign", sign)
                .build();
        String url = base + "/api/l53";
        Request req = new Request.Builder().url(url).post(body).build();
        client.newCall(req).enqueue(new Callback() {
            @Override public void onFailure(Call call, java.io.IOException e) {
                loading = false;
                runOnUiThread(new Runnable() { @Override public void run() { status.setText("请求失败: " + e.getMessage()); } });
            }
            @Override public void onResponse(Call call, Response rsp) {
                try {
                    if (!rsp.isSuccessful()) { final String msg = "HTTP " + rsp.code(); loading = false; runOnUiThread(new Runnable() { @Override public void run() { status.setText(msg); } }); return; }
                    String rspBody = rsp.body().string();
                    org.json.JSONObject obj = new org.json.JSONObject(rspBody);
                    String hex = obj.optString("d", "");
                    String json = Bk53.nativeRc4Decrypt(hex);
                    org.json.JSONObject pageObj = new org.json.JSONObject(json);
                    org.json.JSONArray arr = pageObj.optJSONArray("nums");
                    final int[] nums = new int[arr.length()];
                    for (int i = 0; i < arr.length(); i++) nums[i] = arr.optInt(i);
                    loading = false;
                    runOnUiThread(new Runnable() { @Override public void run() { currentPage = page; render(nums); renderNav(); status.setText("已加载第 " + page + " / " + PAGES + " 页，本页 " + nums.length + " 个数字"); } });
                } catch (Exception e) { loading = false; runOnUiThread(new Runnable() { @Override public void run() { status.setText("解析失败: " + e.getMessage()); } }); }
            }
        });
    }

    static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) { return ""; }
    }
}
