package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
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

// 碧落天 KL40b「镜中之障」：引擎层证书校验（reFlutter 等价）。
// 证书校验不在 Java、也不在普通 native 导出符号里，而在"引擎"深处的一个内部函数上——
// 手（hook）够不着。取数参数由伴生 so 在发包瞬间生成；引擎校验未放行时，参数被静默投毒。
public class prismActivity extends Activity {
    static final String SUM_HASH = "0e167a7e0c343cc835ffa084667ec4da326a139fa4c3f572118f167ba12a7f9d";
    static final int PAGES = 100;

    private TextView status;
    private TextView guard;
    private TextView probeView;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private int currentPage = 1;
    private int loadedMax = 0;
    private boolean loading = false;
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
        tv.setText("镜面成像，真伪倒置。\n"
                + "这一层不看你的凭证，只看“镜中的校验”——它嵌在引擎深处，手够不着。\n"
                + "把镜子看穿，数字才会浮上来。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        // 只读自检：仅显示实现是否完好（中性，不报算法/密钥/载荷来源、不判胜）
        guard = new TextView(this);
        guard.setText("算法自检：—");
        guard.setGravity(Gravity.CENTER);
        guard.setTextSize(12);
        guard.setTypeface(android.graphics.Typeface.MONOSPACE);
        guard.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(guard, Ui.wrap(4));

        // 镜中校验相位（中性展示，不点破手段）
        probeView = new TextView(this);
        probeView.setText("镜中校验：—");
        probeView.setGravity(Gravity.CENTER);
        probeView.setTextSize(12);
        probeView.setTypeface(android.graphics.Typeface.MONOSPACE);
        probeView.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(probeView, Ui.wrap(6));

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
                    else Toast.makeText(prismActivity.this, "页码超出范围 1-" + PAGES, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(prismActivity.this, "请输入页码", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(prismActivity.this)
                        .setTitle("提示")
                        .setMessage("镜子嵌在引擎里，伸手（hook）够不着，喊话（Java 层）也没人应。\n"
                                + "要动它，得先找到镜框上那道刻痕——引擎校验函数有几个很显眼的字节（一串特征常量），\n"
                                + "把它们抹平、让校验恒真，镜子就碎了。\n\n"
                                + "也可以不照镜子：引擎只负责放行，真正送信的密文你完全可以自己按图样刻一遍。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(10));

        box.addView(Ui.banner(this, R.drawable.level_kl40b, 150));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (sha256Hex(ans).equals(SUM_HASH)) {
                    Celebration.show(prismActivity.this, "FLAG_18_KL40b{veil_within_mirror}");
                    PassLog.mark(prismActivity.this, "KL40b");
                } else {
                    Toast.makeText(prismActivity.this,
                            "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        refreshGuard();
        loadPage(1);
    }

    private void refreshGuard() {
        try {
            guard.setText("算法自检：" + FlutterPrism.nativeGetStatus());
        } catch (Throwable t) {
            guard.setText("算法自检：不可用");
        }
        try {
            probeView.setText("镜中校验：" + strip(FlutterPrism.nativeGetProbe()));
        } catch (Throwable t) {
            probeView.setText("镜中校验：不可用");
        }
    }

    private static String strip(String s) {
        if (s == null) return "—";
        int i = s.indexOf('：');
        return i >= 0 ? s.substring(i + 1) : s;
    }

    private void loadPage(final int page) {
        if (loading) return;
        loading = true;
        status.setText("正在请求第 " + page + " 页…");
        FlutterPrism.fetchPage(base, page, new FlutterPrism.Cb() {
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
                            status.setText("第 " + got + " 页没有拿到数字——密文大概没被认可。");
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

    private String readAssets(String name) throws Exception {
        InputStream is = getAssets().open(name);
        byte[] buf = new byte[4096];
        int n = is.read(buf);
        is.close();
        return new String(buf, 0, n, "UTF-8");
    }

    private String baseUrl() {
        try {
            JSONObject cfg = new JSONObject(readAssets("config.json"));
            return NetHost.resolve(cfg.getJSONObject("server").getString("api_base_url"), true);
        } catch (Exception e) {
            return FlutterPrism.BASE;
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
