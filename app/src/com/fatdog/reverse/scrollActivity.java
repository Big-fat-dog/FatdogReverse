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

// 碧落天 KL36「云中锦书」：Flutter/Dart 逆向入门。
// 取数链路是网络求和：伴生 so 对 "page=N&ts=T" 出签名，带签请求 /api/kl36 取数后求和。
// 题眼在随包发出的真实 Flutter 载荷里（不在 DEX、也不在伴生 so 的明文里）。
public class scrollActivity extends Activity {
    static final String SUM_HASH = "f13984c09b7e1be91122083721a200d57fc1e211980760643c5f5992e19d8312";
    static final int PAGES = 100;
    static final int PER_PAGE = 10;

    private TextView status;
    private TextView guard;
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
        tv.setText("一封自天外飘来的锦书，封蜡上压着看不懂的异文。\n"
                + "随信还附了一卷东西，字句被另一种方式压成了原生的模样——\n"
                + "先把它看清楚，信才会开口。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        // 只读自检：只显示摘要自检与载荷/镜像状态，不吐密钥、不判胜
        guard = new TextView(this);
        guard.setText("载荷自检：—");
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

        // 跳页
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
                    else Toast.makeText(scrollActivity.this, "页码超出范围 1-" + PAGES, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(scrollActivity.this, "请输入页码", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(scrollActivity.this)
                        .setTitle("提示")
                        .setMessage("这封信的字句不在这边寻常的代码里，\n"
                                + "它被另一种方式压成了原生的模样，随包一并送出。\n\n"
                                + "先把那卷东西取出来，看清它记事的写法，\n"
                                + "字句就会自己显形；再看懂它给每页盖的印记，\n"
                                + "就能把数字一页页取回来，凑齐总数。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(10));

        box.addView(Ui.banner(this, R.drawable.level_kl36, 150));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (sha256Hex(ans).equals(SUM_HASH)) {
                    Celebration.show(scrollActivity.this, "FLAG_18_KL36{cloud_letter_unrolled}");
                    PassLog.mark(scrollActivity.this, "KL36");
                } else {
                    Toast.makeText(scrollActivity.this,
                            "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        refreshGuard();
        loadPage(1);
    }

    private void refreshGuard() {
        try {
            guard.setText("载荷自检：" + FlutterBridge.nativeGetStatus());
        } catch (Throwable t) {
            guard.setText("载荷自检：不可用");
        }
    }

    private void loadPage(final int page) {
        if (loading) return;
        loading = true;
        status.setText("正在请求第 " + page + " 页…");
        FlutterBridge.fetchPage(base, page, new FlutterBridge.Cb() {
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
                            status.setText("第 " + got + " 页没有拿到数字——签名大概没被认可。");
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
            return FlutterBridge.BASE;
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
