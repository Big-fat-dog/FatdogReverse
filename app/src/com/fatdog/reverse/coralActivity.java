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

import org.json.JSONArray;
import org.json.JSONObject;

// 天地秘境·须弥界 KL43「桥上听风」：JSBridge 协议逆向 + JS 侧消息签名 + 重放。
// 页面把消息 {cmd, page, ts, sign} 递过桥；native 按一张暗表分发（认不得就拦下）。
// 可 sign 不在 native —— 它在那页被混淆的脚本里算。取数链路仍是网络求和。
public class coralActivity extends Activity {
    static final String SUM_HASH = "75ccb454638cc9e28e446e5eec0016b37aa7e014a951ab272289411fd7ae02fd";
    static final int PAGES = 100;
    static final int PER_PAGE = 10;

    private WebView web;
    private TextView status;
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
        tv.setText("桥上风声里来回着消息，每条都裹一枚自签。\n"
                + "页把消息递过桥，native 按一张暗表分发——\n"
                + "表上认得的才放行；签却不在 native，藏在那页被搅乱的脚本里。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        // bridge 协议页
        web = new WebView(this);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        web.setWebViewClient(new WvClient());
        LinearLayout.LayoutParams wlp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(150));
        wlp.topMargin = Ui.dp(8);
        box.addView(web, wlp);

        Button reload = new Button(this);
        reload.setText("重新载入桥页");
        Ui.styleButton(reload);
        reload.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                jsReady = false;
                status.setText("正在重载桥页…");
                web.loadUrl("file:///android_asset/h5/bridge_kl43.html");
            }
        });
        box.addView(reload, Ui.wrap(6));

        status = new TextView(this);
        status.setText("正在加载桥页…");
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
                    else Toast.makeText(coralActivity.this, "页码超出范围 1-" + PAGES, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(coralActivity.this, "请输入页码", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(coralActivity.this)
                        .setTitle("提示")
                        .setMessage("消息不是裸奔的：它是「指令 + 页码 + 时间 + 自签」的结构，签由页面脚本算。\n\n"
                                + "在反编译工程里看 WebView 加载的那页脚本，以及 native 侧的那张分发表——\n"
                                + "表上以数字/短码对应处理函数，认不得的消息会被直接拦下。\n\n"
                                + "真钥不在 so 里，它在被混淆的脚本深处。另有一枚近似的假钥，签了会被拒。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(10));

        box.addView(Ui.banner(this, R.drawable.level_kl43, 150));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (sha256Hex(ans).equals(SUM_HASH)) {
                    Celebration.show(coralActivity.this, "FLAG_19_KL43{wind_on_the_bridge}");
                    PassLog.mark(coralActivity.this, "KL43");
                } else {
                    Toast.makeText(coralActivity.this,
                            "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        web.loadUrl("file:///android_asset/h5/bridge_kl43.html");
    }

    // 具名内部类：WebView 客户端（Frida 可直接 Java.use）
    private class WvClient extends WebViewClient {
        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            jsReady = true;
            status.setText("桥页就绪");
            loadPage(1);
        }
    }

    private void loadPage(final int page) {
        if (loading) return;
        if (!jsReady) {
            status.setText("桥页还没就绪，稍候再试");
            return;
        }
        loading = true;
        status.setText("正在取 bridge 消息并请求第 " + page + " 页…");
        final long ts = System.currentTimeMillis() / 1000;
        // 取一条 bridge 消息（含 JS 侧签名的 sign）
        web.evaluateJavascript("(window.fdMsg)(" + page + "," + ts + ")",
                new ValueCallback<String>() {
                    @Override
                    public void onReceiveValue(String value) {
                        try {
                            if (value == null || "null".equals(value)) {
                                loading = false;
                                status.setText("没取到 bridge 消息——脚本可能没就绪");
                                return;
                            }
                            // evaluateJavascript 回传的是 JSON 编码过的字符串，先解回原文
                            String msg = new JSONArray("[" + value + "]").getString(0);
                            JSONObject obj = new JSONObject(msg);
                            final int gp = obj.getInt("page");
                            final long gts = obj.getLong("ts");
                            String sign = obj.getString("sign");
                            // 交给 native 按 dispatch 表分发
                            String handler = JsBridge.nativeHandle(msg);
                            if ("unknown".equals(handler)) {
                                loading = false;
                                status.setText("桥不认得这条消息（分发未命中）");
                                return;
                            }
                            JsBridge.query(base, gp, gts, sign, new JsBridge.Cb() {
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
                                                status.setText("第 " + got + " 页没拿到数字——签名没被认可。");
                                            } else {
                                                status.setText("分发: query · 已加载第 " + got + " / " + PAGES + " 页");
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
                        } catch (Exception e) {
                            loading = false;
                            status.setText("消息解析失败：" + e.getMessage());
                        }
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
            return JsBridge.BASE;
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
