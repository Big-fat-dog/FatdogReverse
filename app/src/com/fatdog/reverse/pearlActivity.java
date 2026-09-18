package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.webkit.ValueCallback;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.InputStream;
import java.security.MessageDigest;

import org.json.JSONObject;

// 天地秘境·须弥界 KL44「暗流涌动」：JSBridge 签名拦截 + JS 层加密（双层）。
// 第一层：页面脚本把明文参数搅成密文 enc（密钥在混淆的 JS 里）；
// 第二层：native 用藏在 so 里的钥再签一道。任一层不对，服务端都不放数。
// native 还立着反调试哨兵——被调则改用诱饵钥，签了也白签。取数链路仍是网络求和。
public class pearlActivity extends Activity {
    static final String SUM_HASH = "9997afaed60b6ff176d49dead326114e0433b32ac90da2da43efa5c484780ba9";
    static final int PAGES = 100;
    static final int PER_PAGE = 10;

    private WebView web;
    private TextView status;
    private TextView guard;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private int currentPage = 1;
    private int loadedMax = 0;
    private boolean loading = false;
    private boolean jsReady = false;
    private String base;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        base = baseUrl();

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(14), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("暗流底下压着两层锁。\n"
                + "页面先把参数搅成密文，native 再补上一道签——\n"
                + "两把钥不同、两道算法不同，缺哪层都取不到数。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        // 第一层：JS 加密页
        web = new WebView(this);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        web.setWebViewClient(new WvClient());
        LinearLayout.LayoutParams wlp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(140));
        wlp.topMargin = Ui.dp(8);
        box.addView(web, wlp);

        // 只读自检：只显示守卫状态，不判胜、不吐钥
        guard = new TextView(this);
        guard.setText("反调试自检：—");
        guard.setGravity(Gravity.CENTER);
        guard.setTextSize(12);
        guard.setTypeface(android.graphics.Typeface.MONOSPACE);
        guard.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(guard, Ui.wrap(6));

        Button refresh = new Button(this);
        refresh.setText("刷新自检");
        Ui.styleButton(refresh);
        refresh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                refreshGuard();
            }
        });
        box.addView(refresh, Ui.wrap(6));

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
            c.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
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
            @Override
            public void onClick(View v) {
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
            @Override
            public void onClick(View v) {
                if (currentPage < PAGES) loadPage(currentPage + 1);
            }
        });

        box.addView(navRow, Ui.fullWidth(14));

        // 跳转
        LinearLayout jumpRow = new LinearLayout(this);
        jumpRow.setOrientation(LinearLayout.HORIZONTAL);
        jumpRow.setGravity(Gravity.CENTER_VERTICAL);
        final EditText pageIn = new EditText(this);
        pageIn.setHint("页码 1-" + PAGES);
        pageIn.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        jumpRow.addView(pageIn);
        Button jump = new Button(this);
        jump.setText("跳转");
        Ui.styleButton(jump);
        jumpRow.addView(jump);
        jump.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = pageIn.getText().toString().trim();
                try {
                    int p = Integer.parseInt(s);
                    if (p >= 1 && p <= PAGES) loadPage(p);
                    else Toast.makeText(pearlActivity.this, "页码超出范围 1-" + PAGES, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(pearlActivity.this, "请输入页码", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(jumpRow, Ui.fullWidth(10));

        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入 1000 个数字的总和");
        ansIn.setLayoutParams(Ui.fullWidth(22));
        box.addView(ansIn);

        Button subBtn = new Button(this);
        subBtn.setText("提交答案");
        Ui.styleButton(subBtn);
        box.addView(subBtn, Ui.wrap(14));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(pearlActivity.this)
                        .setTitle("提示")
                        .setMessage("两层锁，两把钥，两道算法。\n\n"
                                + "第一层在页面脚本里：它把明文参数搅成一段 hex 密文，\n"
                                + "密钥就藏在被搅乱的那堆代码里（原文里看不见，得自己解）。\n"
                                + "第二层在 native：它对「明文参数 + 那段密文」再补一道签名，钥藏在 so 里。\n\n"
                                + "so 里还立着反调试哨兵：一旦判定被调，它就会换成诱饵钥——签出来照样被拒。\n"
                                + "另有一枚近似的假钥，别认错。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(10));

        box.addView(Ui.banner(this, R.drawable.level_kl44, 150));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (sha256Hex(ans).equals(SUM_HASH)) {
                    Celebration.show(pearlActivity.this, "FLAG_19_KL44{undertow_surging}");
                    PassLog.mark(pearlActivity.this, "KL44");
                } else {
                    Toast.makeText(pearlActivity.this,
                            "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        refreshGuard();
        web.loadUrl("file:///android_asset/h5/sign_kl44.html");
    }

    private void refreshGuard() {
        try {
            guard.setText("反调试自检：" + SignBridge.nativeStatus());
        } catch (Throwable t) {
            guard.setText("反调试自检：不可用");
        }
    }

    // 具名内部类：WebView 客户端（Frida 可直接 Java.use）
    private class WvClient extends WebViewClient {
        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            jsReady = true;
            status.setText("签名页就绪");
            loadPage(1);
        }
    }

    private void loadPage(final int page) {
        if (loading) return;
        if (!jsReady) {
            status.setText("签名页还没就绪，稍候再试");
            return;
        }
        loading = true;
        status.setText("正在加密并请求第 " + page + " 页…");
        final long ts = System.currentTimeMillis() / 1000;
        // 第一层：向页面要 JS 侧算出的密文 enc
        web.evaluateJavascript("(window.fdEnc)(" + page + "," + ts + ")",
                new ValueCallback<String>() {
                    @Override
                    public void onReceiveValue(String value) {
                        String enc = value == null ? "" : value.replace("\"", "").trim();
                        if (enc.length() < 8) {
                            loading = false;
                            status.setText("没取到第一层密文——脚本可能没就绪");
                            return;
                        }
                        // 第二层：交给 native 做 HMAC 二次签名
                        String sign;
                        try {
                            sign = SignBridge.nativeBridgeSign(page, ts, enc);
                        } catch (Throwable t) {
                            loading = false;
                            status.setText("native 签名失败：" + t.getMessage());
                            return;
                        }
                        SignBridge.fetch(base, page, ts, enc, sign, new SignBridge.Cb() {
                            @Override
                            public void onPage(final int got, final int[] nums) {
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        loading = false;
                                        currentPage = got;
                                        if (got > loadedMax) loadedMax = got;
                                        render(nums);
                                        renderNav();
                                        if (nums.length == 0) {
                                            status.setText("第 " + got + " 页没拿到数字——双层里有一层没对上。");
                                        } else {
                                            status.setText("双层通过 · 已加载第 " + got + " / " + PAGES + " 页");
                                        }
                                    }
                                });
                            }

                            @Override
                            public void onError(final String err) {
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        loading = false;
                                        status.setText("请求失败: " + err + "（可重试）");
                                    }
                                });
                            }
                        });
                    }
                });
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
            chip.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
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
                @Override
                public void onClick(View v) {
                    if (fp != currentPage) loadPage(fp);
                }
            });
            pageBar.addView(chip, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        }
    }

    private String baseUrl() {
        try {
            InputStream is = getAssets().open("config.json");
            byte[] buf = new byte[4096];
            int n = is.read(buf);
            is.close();
            JSONObject cfg = new JSONObject(new String(buf, 0, n, "UTF-8"));
            return NetHost.resolve(cfg.getJSONObject("server").getString("api_base_url"), true);
        } catch (Exception e) {
            return SignBridge.BASE;
        }
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
