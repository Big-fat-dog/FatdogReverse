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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;

import org.json.JSONObject;

// 天地秘境·须弥界 KL42「沙中藏贝」：H5 资源加密 + JS 层加密。
// 资源不是明文躺在 assets 里——它被 RC4 锁进一个容器，钥匙藏在 libwebvault.so 的异或数组里；
// native 还原出页面后，签名又不归 native 管，而是由页面里那段被混淆的前端脚本算。
// 取数链路仍是网络求和：页面 JS 算签 → 带签请求 /api/kl42 取数后求和。
public class reefActivity extends Activity {
    static final String SUM_HASH = "dd6499288e8200fb11db3981400db73371a49a97ea543d4cde7675e54eaff030";
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
        tv.setText("潮水退去，贝壳里裹着一页被锁起来的 H5。\n"
                + "资源不是明文躺在那里——native 会把它解出来，\n"
                + "可签不在 native 手里，藏在这页前端的脚本里。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        // H5 资源页：native 解密容器后 loadData 载入
        web = new WebView(this);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        web.setWebViewClient(new WvClient());
        LinearLayout.LayoutParams wlp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(170));
        wlp.topMargin = Ui.dp(8);
        box.addView(web, wlp);

        Button reload = new Button(this);
        reload.setText("重新载入资源");
        Ui.styleButton(reload);
        reload.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                loadVault();
            }
        });
        box.addView(reload, Ui.wrap(6));

        status = new TextView(this);
        status.setText("正在还原资源…");
        status.setGravity(Gravity.CENTER);
        status.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(status, Ui.wrap(8));

        // 数字网格：5 列 x 2 行，最多 10 个数字
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

        // 分页导航：上一页 / [页码窗口] / 下一页
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

        // 跳转到指定页
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
                    else Toast.makeText(reefActivity.this, "页码超出范围 1-" + PAGES, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(reefActivity.this, "请输入页码", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(reefActivity.this)
                        .setTitle("提示")
                        .setMessage("资源容器不是给人直接看的：它躺在 assets 里，密文一片。\n\n"
                                + "先弄清 native 用哪套算法、哪把钥匙把它还原成页面；\n"
                                + "再看还原出来的那页前端脚本——被搅乱的那堆代码里，才藏着真正的签名密钥。\n\n"
                                + "so 与前端里各留了一枚近似的钥，其中一枚是诱饵——仔细比对拼写。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(10));

        box.addView(Ui.banner(this, R.drawable.level_kl42, 150));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (sha256Hex(ans).equals(SUM_HASH)) {
                    Celebration.show(reefActivity.this, "FLAG_19_KL42{sand_hidden_shell}");
                    PassLog.mark(reefActivity.this, "KL42");
                } else {
                    Toast.makeText(reefActivity.this,
                            "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        loadVault();
    }

    // 具名内部类：WebView 客户端（Frida 可直接 Java.use）
    private class WvClient extends WebViewClient {
        @Override
        public void onPageFinished(WebView view, String url) {
            super.onPageFinished(view, url);
            jsReady = true;
            status.setText("资源已还原 · 脚本就绪");
            loadPage(1);
        }
    }

    private void loadVault() {
        jsReady = false;
        status.setText("正在还原资源…");
        try {
            byte[] enc = readAssetBytes("h5/vault_kl42.bin");
            String html = WebVault.nativeDecryptAsset(enc);
            if (html == null || html.length() == 0) {
                status.setText("资源还原为空——钥匙或算法不对？");
                return;
            }
            web.loadDataWithBaseURL(base, html, "text/html", "utf-8", null);
        } catch (Throwable t) {
            status.setText("资源还原失败：" + t.getMessage());
        }
    }

    private void loadPage(final int page) {
        if (loading) return;
        if (!jsReady) {
            status.setText("脚本还没就绪，稍候再试");
            return;
        }
        loading = true;
        status.setText("正在向页面取签并请求第 " + page + " 页…");
        final long ts = System.currentTimeMillis() / 1000;
        // 签名由页面内前端脚本计算，native 只负责把它取回来
        web.evaluateJavascript("(window.fdSign)(" + page + "," + ts + ")",
                new ValueCallback<String>() {
                    @Override
                    public void onReceiveValue(String value) {
                        String sign = value == null ? "" : value.replace("\"", "").trim();
                        if (sign.length() != 64) {
                            loading = false;
                            status.setText("没从页面取到签名——脚本可能没就绪");
                            return;
                        }
                        WebVault.fetchPage(base, page, ts, sign, new WebVault.Cb() {
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
                                            status.setText("第 " + got + " 页没有拿到数字——签名没被认可。");
                                        } else {
                                            status.setText("已加载第 " + got + " / " + PAGES + " 页，本页 " + nums.length + " 个数字");
                                        }
                                    }
                                });
                            }

                            @Override
                            public void onError(final String msg) {
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        loading = false;
                                        status.setText("请求失败: " + msg + "（可重试）");
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

    private byte[] readAssetBytes(String name) throws Exception {
        InputStream is = getAssets().open(name);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        is.close();
        return bos.toByteArray();
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
            return WebVault.BASE;
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
