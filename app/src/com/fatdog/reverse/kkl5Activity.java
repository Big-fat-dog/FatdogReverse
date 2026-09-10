package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.TimeUnit;

import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * KKL5 · 诛仙台。
 *
 * onCreate 被"抽成 native"：关键门禁不在 Java 里，而是 libkkl5.so 的 VM
 * 字节码解释执行（对齐 360 加固 native onCreate 还原）。Java 侧只负责
 * 构建可交互的视图、调用 nativeSign 拿 AES-128-CBC + HMAC 的取数签名、
 * 再把服务端返回的密文交给 native 解。
 */
public class kkl5Activity extends Activity {
    private static final int PAGES = 100;
    private static final String SUM_HASH = "5c1f9a36a76360acdb86b6859da42f3ea7abe57ba5f5d836066039885f619924";

    private final TextView[] cells = new TextView[10];
    private TextView status;
    private LinearLayout pageBar;
    private EditText ansIn;
    private int currentPage = 1;
    private boolean loading = false;
    private boolean onCreateOk = false;
    private int answered = 0;
    private String base;
    private OkHttpClient client;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        base = NetHost.httpBase();
        client = new OkHttpClient.Builder()
                .connectTimeout(6, TimeUnit.SECONDS)
                .readTimeout(6, TimeUnit.SECONDS)
                .build();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KKL5 · 诛仙台（★★★★★）\n\n"
                + "外壳把本页的 onCreate 抽成 native：\n"
                + "  · onCreate 门禁由 VM 字节码解释执行\n"
                + "  · 取数走 AES-128-CBC + HMAC-SHA256 复合签名\n"
                + "  · 翻页触发 open → sign → commit 三点记账\n\n"
                + "数据只在服务端；VM 字节码、密钥、判胜都不在 Java 里。");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        status = new TextView(this);
        status.setTextColor(Color.LTGRAY);
        status.setTypeface(Typeface.MONOSPACE);
        status.setTextSize(12);
        status.setGravity(Gravity.CENTER);
        root.addView(status, Ui.fullWidth(6));

        Button scanBtn = new Button(this);
        scanBtn.setText("守卫自检");
        Ui.styleButton(scanBtn);
        scanBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                status.setText(Kkl5Native.nativeStatus());
            }
        });
        root.addView(scanBtn, Ui.wrap(10));

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
        root.addView(grid, Ui.fullWidth(12));

        LinearLayout navRow = new LinearLayout(this);
        navRow.setOrientation(LinearLayout.HORIZONTAL);
        navRow.setGravity(Gravity.CENTER_VERTICAL);
        Button prev = new Button(this);
        prev.setText("◀ 上一页");
        Ui.styleButton(prev);
        prev.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (!loading && currentPage > 1) loadPage(currentPage - 1);
            }
        });
        navRow.addView(prev);
        HorizontalScrollView hsv = new HorizontalScrollView(this);
        hsv.setHorizontalScrollBarEnabled(false);
        pageBar = new LinearLayout(this);
        pageBar.setOrientation(LinearLayout.HORIZONTAL);
        hsv.addView(pageBar);
        navRow.addView(hsv, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        Button next = new Button(this);
        next.setText("下一页 ▶");
        Ui.styleButton(next);
        next.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (!loading && currentPage < PAGES) loadPage(currentPage + 1);
            }
        });
        navRow.addView(next);
        root.addView(navRow, Ui.fullWidth(10));

        ansIn = new EditText(this);
        ansIn.setHint("输入总和 sha256（64 位 hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        int pad = Ui.dp(10);
        ansIn.setPadding(pad, pad, pad, pad);
        root.addView(ansIn, Ui.fullWidth(10));

        Button subBtn = new Button(this);
        subBtn.setText("提交答案");
        Ui.styleButton(subBtn);
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (ans.isEmpty()) {
                    Toast.makeText(kkl5Activity.this, "请输入答案", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (ans.equalsIgnoreCase(SUM_HASH)) {
                    Celebration.show(kkl5Activity.this, "FLAG_18_KKL5{ascension_of_the_immortals}");
                    PassLog.mark(kkl5Activity.this, "KKL5");
                } else {
                    Toast.makeText(kkl5Activity.this, "加和不对，先取回全部 100 页。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(kkl5Activity.this)
                        .setTitle("提示")
                        .setMessage("诛仙台是收官卷：\n\n"
                                + "① onCreate 被抽成 native，关键判断在 VM 字节码里逐条解释执行；\n"
                                + "② 取数签名是 AES-128-CBC + HMAC 复合结构，密钥由标记派生；\n"
                                + "③ VM 字节码是滚动 XOR 加密的，静态看不到明文指令；\n"
                                + "④ 两个标记中有一个是诱饵，仔细对比拼写差异；\n"
                                + "⑤ 自检按钮只读，不判胜——真机关在翻页取数链路。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));
        root.addView(Ui.banner(this, R.drawable.level_kkl5, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);

        // onCreate 抽取：先让 native VMP 跑门禁，再决定是否放行取数。
        final String gate = Kkl5Native.nativeOnCreate(this);
        onCreateOk = gate != null && gate.startsWith("OK");
        if (onCreateOk) {
            String dexInfo = loadBusinessDex();
            status.setText("onCreate VM 门禁通过，" + dexInfo + "，准备取数。");
            loadPage(1);
        } else {
            status.setText("门禁未通过：" + gate + "\nso 可能被 patch / 环境被 hook。");
        }
    }

    /** 内存加载 assets/kkl5 的加密业务 DEX（不落盘）。 */
    private String loadBusinessDex() {
        try {
            java.io.InputStream is = getAssets().open("kkl5/ascension_altar.bin");
            byte[] sealed = readAll(is);
            byte[] dex = Kkl5Native.nativeUnseal(sealed);
            if (dex == null || dex.length < 8) return "业务 DEX 未解封";
            java.io.File tmp = new java.io.File(getCacheDir(), "kkl5_biz.dex");
            java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp);
            fos.write(dex);
            fos.close();
            ClassLoader cl = getClassLoader();
            dalvik.system.DexClassLoader loader = new dalvik.system.DexClassLoader(
                    tmp.getAbsolutePath(), getCacheDir().getAbsolutePath(), null, cl);
            Class<?> c = loader.loadClass("com.fatdog.reverse.kkl5.GateKeeper5");
            Object magic = c.getMethod("magic").invoke(null);
            return "业务 DEX 已内存加载（" + magic + "）";
        } catch (Throwable t) {
            return "业务 DEX 加载失败：" + t.getMessage();
        }
    }

    private static byte[] readAll(java.io.InputStream is) throws java.io.IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        is.close();
        return bos.toByteArray();
    }
        private void loadPage(final int page) {
        if (loading || !onCreateOk) return;
        loading = true;
        status.setText("正在请求第 " + page + " 页…");
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    final long ts = System.currentTimeMillis() / 1000;
                    String signed = Kkl5Native.nativeSign(page, ts);
                    if (signed == null || signed.indexOf('|') < 0) {
                        throw new IllegalStateException("native 签名被守卫拒绝");
                    }
                    String enc = signed.substring(0, signed.indexOf('|'));
                    String sign = signed.substring(signed.indexOf('|') + 1);
                    RequestBody body = new FormBody.Builder()
                            .add("page", String.valueOf(page))
                            .add("ts", String.valueOf(ts))
                            .add("enc", enc)
                            .add("sign", sign)
                            .build();
                    Request req = new Request.Builder().url(base + "/api/kkl5")
                            .header("User-Agent", "Fatdog/1.0 (Android)")
                            .post(body).build();
                    Response resp = client.newCall(req).execute();
                    final int[] nums;
                    try {
                        String payload;
                        if (!resp.isSuccessful()) {
                            throw new IllegalStateException("HTTP " + resp.code()
                                    + "（守卫触发或密钥被投毒）");
                        }
                        JSONObject jo = new JSONObject(resp.body().string());
                        String ivHex = jo.getString("iv");
                        String dHex = jo.getString("d");
                        String rspSign = jo.getString("sign");
                        // 响应 HMAC 验签：加密字节被篡改则立即拒绝
                        if (!Kkl5Native.nativeVerifyResponse(page, ts, ivHex, dHex, rspSign)) {
                            throw new IllegalStateException("响应签名校验失败");
                        }
                        byte[] sealed = hexToBytes(ivHex + dHex);
                        byte[] plain = Kkl5Native.nativeUnseal(sealed);
                        if (plain == null) throw new IllegalStateException("响应解密失败");
                        payload = new String(plain, "UTF-8");
                        JSONObject pageObj = new JSONObject(payload);
                        JSONArray arr = pageObj.getJSONArray("nums");
                        nums = new int[arr.length()];
                        for (int i = 0; i < arr.length(); i++) nums[i] = arr.getInt(i);
                    } finally {
                        resp.close();
                    }
                    final int commit = Kkl5Native.nativeCommit(page, nums.length);
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            loading = false;
                            currentPage = page;
                            render(nums);
                            renderNav(page);
                            answered = Math.max(answered, page);
                            status.setText("第 " + page + "/" + PAGES + " 页已取，"
                                    + nums.length + " 个数"
                                    + (commit == 0 ? "（记账闭合）" : "（核账失败 " + commit + "）"));
                        }
                    });
                } catch (final Throwable t) {
                    Kkl5Native.nativeRollback();
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            loading = false;
                            status.setText("请求失败: " + t + "\n已撤销挂账，可重试。");
                        }
                    });
                }
            }
        }).start();
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

    private void renderNav(int page) {
        pageBar.removeAllViews();
        int win = 3;
        int start = Math.max(1, page - win);
        int end = Math.min(PAGES, page + win);
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
            boolean sel = (p == page);
            g.setColor(sel ? 0xFFFB7299 : 0x33222222);
            chip.setBackground(g);
            chip.setTextColor(sel ? Color.WHITE : 0xFFCCCCCC);
            chip.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) {
                    if (!loading) loadPage(fp);
                }
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            lp.setMargins(Ui.dp(2), 0, Ui.dp(2), 0);
            pageBar.addView(chip, lp);
        }
    }

    private static byte[] hexToBytes(String s) {
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
