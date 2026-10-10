package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
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

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

// 太玄之初 KKL5 · 诛仙台（★★★★★ 收官卷，服务端取数）。
// 这里的机关不是壳，是一台自造的虚拟机：它一步步把钥匙从标记里算出来，
// 指令密文按前一条自反馈加密——解得开第 N 条，才有第 N+1 条。
// 取数走两层加密复合（内层分组 + 外层流式）叠一层摘要签名；五个 so 缺一不可。
// 完整性守卫一旦命中，主钥被静默污染，服务端全程不给你报错。
public class kkl5Activity extends Activity {
    static final String SUM_HASH = "206125c6e7523ba7c0301144ac24eea9";
    static final int PAGES = 100;
    static final int PER_PAGE = 10;

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private EditText ansIn;
    private int currentPage = 1;
    private boolean loading = false;
    private boolean gateOk = false;
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
                + "这一页的 onCreate 被整个抽成了 native：\n"
                + "门禁不在 Java 里，而在自造虚拟机逐条解开的密文指令里。\n"
                + "虚拟机一步步算出的那把钥匙，又去喂两层加密复合——\n"
                + "内层分组、外层流式，再叠一层摘要签名。\n\n"
                + "五个 so 首尾相扣：缺一环，钥匙算不出；\n"
                + "环境被标记可疑，取回的数是废的。\n\n"
                + "取满 100 页（每页 10 个数），求和后取摘要提交。");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        status = new TextView(this);
        status.setText("正在跑 onCreate 门禁…");
        status.setTextColor(Color.LTGRAY);
        status.setTypeface(Typeface.MONOSPACE);
        status.setTextSize(12);
        status.setGravity(Gravity.CENTER);
        root.addView(status, Ui.fullWidth(6));

        Button scanBtn = new Button(this);
        scanBtn.setText("环境自检");
        Ui.styleButton(scanBtn);
        scanBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                status.setText(Kkl5Native.nativeStatus());
            }
        });
        root.addView(scanBtn, Ui.wrap(10));

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
        root.addView(grid, Ui.fullWidth(12));

        // 分页
        LinearLayout navRow = new LinearLayout(this);
        navRow.setOrientation(LinearLayout.HORIZONTAL);
        navRow.setGravity(Gravity.CENTER_VERTICAL);
        Button prev = new Button(this);
        prev.setText("◀ 上一页");
        Ui.styleButton(prev);
        navRow.addView(prev, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        prev.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (!loading && currentPage > 1) loadPage(currentPage - 1);
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
        navRow.addView(next, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        next.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (!loading && currentPage < PAGES) loadPage(currentPage + 1);
            }
        });
        root.addView(navRow, Ui.fullWidth(10));

        ansIn = new EditText(this);
        ansIn.setHint("输入总和摘要（32 位 hex）");
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
                                + "① onCreate 被抽成 native，关键判断在自造虚拟机的密文指令里；\n"
                                + "② 这台虚拟机的指令按前一条自反馈加密，静态段看不到明文指令；\n"
                                + "③ 取数是两层加密复合 + 一层摘要签名，密钥由标记派生；\n"
                                + "④ 两个标记一真一假，拼写只差一点，仔细比对；\n"
                                + "⑤ 自检按钮只读，不判胜——真机关在取数链路。\n\n"
                                + "取证方向：把取数跑通的每一步摸清楚，或在干净环境里把\n"
                                + "派生链整条复刻出来——答案只有数字之和的摘要。")
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
        gateOk = gate != null && gate.startsWith("OK");
        if (gateOk) {
            final String dexInfo = loadBusinessDex();
            status.setText("onCreate 门禁通过，" + dexInfo + "，准备取数。");
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
        if (loading || !gateOk) return;
        loading = true;
        runOnUiThread(new Runnable() {
            @Override public void run() { status.setText("正在请求第 " + page + " 页…"); }
        });
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    final long ts = System.currentTimeMillis() / 1000;
                    final String token = Kkl5Native.nativeSign(page, ts);
                    final int bar = token == null ? -1 : token.indexOf('|');
                    if (bar <= 0) {
                        throw new IllegalStateException("取数内核未就绪（五 so 缺一或主钥已被污染）");
                    }
                    final String enc = token.substring(0, bar);
                    final String sign = token.substring(bar + 1);
                    final String url = base + "/api/kkl5?page=" + page + "&ts=" + ts
                            + "&enc=" + enc + "&sign=" + sign;
                    Request req = new Request.Builder().url(url)
                            .header("User-Agent", "Fatdog/1.0 (Android)")
                            .get().build();
                    Response resp = client.newCall(req).execute();
                    final int[] nums;
                    try {
                        if (!resp.isSuccessful()) {
                            throw new IllegalStateException("HTTP " + resp.code()
                                    + "（门没开：内核不齐、标记用错，或环境已被标记可疑）");
                        }
                        JSONObject jo = new JSONObject(resp.body().string());
                        byte[] sealed = hexToBytes(jo.getString("d"));
                        byte[] plain = Kkl5Native.nativeUnseal(sealed);
                        if (plain == null) throw new IllegalStateException("响应解密失败");
                        JSONObject pageObj = new JSONObject(new String(plain, "UTF-8"));
                        JSONArray arr = pageObj.getJSONArray("nums");
                        nums = new int[arr.length()];
                        for (int i = 0; i < arr.length(); i++) nums[i] = arr.getInt(i);
                    } finally {
                        resp.close();
                    }
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            loading = false;
                            currentPage = page;
                            render(nums);
                            renderNav(page);
                            status.setText("第 " + page + "/" + PAGES + " 页已取，"
                                    + nums.length + " 个数（门开着）");
                        }
                    });
                } catch (final Throwable t) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            loading = false;
                            status.setText("请求失败: " + t + "\n可重试，也可「环境自检」看状态。");
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
            g.setColor(sel ? 0xFFFB7299 : (ThemeKit.isDark(this) ? 0xFF2A2A33 : 0xFFF1F1F4));
            chip.setBackground(g);
            chip.setTextColor(sel ? 0xFFFFFFFF : (ThemeKit.isDark(this) ? 0xFFD8D8E0 : 0xFF3A3A42));
            chip.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) {
                    if (!loading && fp != currentPage) loadPage(fp);
                }
            });
            pageBar.addView(chip, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
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
