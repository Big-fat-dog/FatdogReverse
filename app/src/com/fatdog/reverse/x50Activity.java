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
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Native大陆 L50 幽暗深渊（vtable 分发 · 全动态注册 · 跨层回调 · AES-128-ECB + SHA-256）
 *
 * libcrane.so 的导出表**只剩 JNI_OnLoad**（原有的 Java_* 静态命名导出已改成
 * RegisterNatives 动态注册，注册用的类名/方法名/签名全是运行时解出的密文）；
 * 真正的算法类收在匿名命名空间里，nm -D 看不到任何算法名。
 *
 * Java 侧实例桥（Bk50）：
 *   构造函数用反射造出一个 R8 改名类的实例 → bindHolder 交给 so 缓存 →
 *   so 侧加密时回调该实例的实例方法取 AES 密钥尾段。
 *   三个主力方法是**实例 native**：nativeEnc / nativeSign / getKeyHint。
 *
 * 破解路线：
 *   ① IDA 打开 libcrane.so：导出表只有 JNI_OnLoad → 进它看注册了哪几个名字（密文解出）；
 *   ② 顺 bindHolder → GetMethodID → CallObjectMethod 反查 Java 侧回调目标；
 *   ③ jadx：Bk50 反射造了 R8 改名类的实例，找到密文数组 + 私有解密函数；
 *   ④ 掩码常量在 so 里、盐在 Java 里 —— 缺一解出乱码；Frida hook CallObjectMethod 逐页取数。
 *
 * Flag: FLAG_18_L50{abyssal_depths}
 */
public class x50Activity extends Activity {

    private static final int PAGES = 100;
    private static final int PER_PAGE = 10;
    private static final String SUM_HASH = "0b5ad1c0fc3c02619f9f7043eaee6269c3f49215e5d135adbd7fc8120219241f";

    private OkHttpClient client;
    private String base;
    private boolean loading;
    private int currentPage = 1;
    private Bk50 bridge;   // 有状态的 JNI 桥：构造时反射造取件器实例并交给 native

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private EditText pageInput;
    private EditText ansInput;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        base = NetHost.httpsBase();
        initClient();
        bridge = new Bk50();

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(14), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("L50 · 幽暗深渊（★★★★★）\n"
                + "深渊里住着一大家子人，个个自称会开门。\n"
                + "可真正会开锁的，只有藏在其中的两位；\n"
                + "其余的，不过是凑数的远房亲戚。\n"
                + "循着那股真正拧动门轴的气力，别被满堂的喧闹带偏。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        status = new TextView(this);
        status.setText("准备中…");
        status.setGravity(Gravity.CENTER);
        status.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(status, Ui.wrap(8));

        // 数字网格：5 列 x 2 行
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

        // 分页导航
        LinearLayout navRow = new LinearLayout(this);
        navRow.setOrientation(LinearLayout.HORIZONTAL);
        navRow.setGravity(Gravity.CENTER_VERTICAL);

        Button prev = new Button(this);
        prev.setText("◀ 上一页");
        Ui.styleButton(prev);
        navRow.addView(prev, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        prev.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (currentPage > 1) loadPage(currentPage - 1);
            }
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
            @Override public void onClick(View v) {
                if (currentPage < PAGES) loadPage(currentPage + 1);
            }
        });

        box.addView(navRow, Ui.fullWidth(14));

        // 跳转到指定页
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
                    else Toast.makeText(x50Activity.this, "页码超出范围 1-" + PAGES, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(x50Activity.this, "请输入页码", Toast.LENGTH_SHORT).show();
                }
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
                new AlertDialog.Builder(x50Activity.this)
                        .setTitle("提示")
                        .setMessage("那一家子人，都顶着一个共同的姓氏，\n"
                                + "排在一张看不见的名册上。\n\n"
                                + "名册上第一个名字，才是会被真正喊到的那位；\n"
                                + "其余的名字，任凭怎么热闹，都无人搭理。\n\n"
                                + "顺着名册往下数，能数出一长串——\n"
                                + "可真正动手开门的，从头到尾只有两位。\n"
                                + "盯紧被喊到的那两个，别在满册的名字里迷了眼。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(10));

        box.addView(Ui.banner(this, R.drawable.level_50, 150));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansInput.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(x50Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                if (sha256Hex(ans).equals(SUM_HASH)) {
                    Celebration.show(x50Activity.this, "FLAG_18_L50{abyssal_depths}");
                    PassLog.mark(x50Activity.this, "L50");
                } else {
                    Toast.makeText(x50Activity.this, "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        loadPage(1);
    }

    private void render(int[] nums) {
        for (int i = 0; i < cells.length; i++) {
            if (i < nums.length) {
                cells[i].setText(String.valueOf(nums[i]));
                cells[i].setVisibility(View.VISIBLE);
            } else {
                cells[i].setVisibility(View.INVISIBLE);
            }
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
                @Override public void onClick(View v) {
                    if (fp != currentPage) loadPage(fp);
                }
            });
            pageBar.addView(chip, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        }
    }

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
        status.setText("正在请求第 " + page + " 页…");

        final long ts = System.currentTimeMillis() / 1000;
        String enc = bridge.nativeEnc(page, ts);
        String sign = bridge.nativeSign(enc);

        // GET 请求：enc, sign, ts
        String url = base + "/api/l50?enc=" + enc + "&sign=" + sign + "&ts=" + ts;

        Request req = new Request.Builder()
                .url(url)
                .get()
                .build();

        client.newCall(req).enqueue(new Callback() {
            @Override public void onFailure(Call call, java.io.IOException e) {
                loading = false;
                runOnUiThread(new Runnable() {
                    @Override public void run() { status.setText("请求失败: " + e.getMessage() + "（可重试）"); }
                });
            }
            @Override public void onResponse(Call call, Response rsp) {
                try {
                    if (!rsp.isSuccessful()) {
                        final String msg = "HTTP " + rsp.code();
                        loading = false;
                        runOnUiThread(new Runnable() {
                            @Override public void run() { status.setText(msg); }
                        });
                        return;
                    }
                    String rspBody = rsp.body().string();
                    org.json.JSONObject obj = new org.json.JSONObject(rspBody);
                    org.json.JSONArray arr = obj.optJSONArray("nums");
                    final int[] nums = new int[arr.length()];
                    for (int i = 0; i < arr.length(); i++) nums[i] = arr.optInt(i);
                    loading = false;
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            currentPage = page;
                            render(nums);
                            renderNav();
                            status.setText("已加载第 " + page + " / " + PAGES + " 页，本页 " + nums.length + " 个数字");
                        }
                    });
                } catch (Exception e) {
                    loading = false;
                    runOnUiThread(new Runnable() {
                        @Override public void run() { status.setText("解析失败: " + e.getMessage()); }
                    });
                }
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
        } catch (Exception e) {
            return "";
        }
    }
}
