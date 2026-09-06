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

// 太玄之初 KKL3 · 断魂谷（★★★，服务端取数）。
// libkkl3.so 的四路哨兵只做一件事：命中后把取数 HMAC 密钥翻 1 bit，
// 服务端 /api/kkl3 持续 403。数字仍只在本地服务端，检测按钮不通关。
public class kkl3Activity extends Activity {
    static final String SUM_HASH = "5b675c4a63fbc84ebc0478f244d3c63093d57d6a1eca7df8618dbf1485c92fd7";
    static final int PAGES = 100;
    static final int PER_PAGE = 10;

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private int currentPage = 1;
    private boolean loading = false;
    private String base;
    private OkHttpClient client;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        base = NetHost.httpBase();
        client = new OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KKL3 · 断魂谷（★★★）\n\n"
                + "libkkl3.so 四路哨兵守着取数签名：\n"
                + "  ① ptrace/TracerPid\n"
                + "  ② maps 加载特征（frida/gadget/librun）\n"
                + "  ③ 27042 端口探测\n"
                + "  ④ frida 线程名指纹\n\n"
                + "任一命中，签名密钥立即翻 1 bit——\n"
                + "服务端验签 403，数据仍在服务端。");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        status = new TextView(this);
        status.setText("点击「哨兵自检」查看状态，翻页即触发真实签名。");
        status.setTextColor(Color.LTGRAY);
        status.setTypeface(Typeface.MONOSPACE);
        status.setTextSize(12);
        status.setGravity(Gravity.CENTER);
        root.addView(status, Ui.fullWidth(6));

        Button scanBtn = new Button(this);
        scanBtn.setText("哨兵自检");
        Ui.styleButton(scanBtn);
        scanBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                status.setText(Kkl3Native.nativeStatus());
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

        final EditText ansIn = new EditText(this);
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
                    Toast.makeText(kkl3Activity.this, "请输入答案", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (ans.equalsIgnoreCase(SUM_HASH)) {
                    Celebration.show(kkl3Activity.this, "FLAG_18_KKL3{valley_of_the_sentinel}");
                    PassLog.mark(kkl3Activity.this, "KKL3");
                } else {
                    Toast.makeText(kkl3Activity.this, "加和不对，先取回全部 100 页。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(kkl3Activity.this)
                        .setTitle("提示")
                        .setMessage("断魂谷要拆的是「签名前哨兵」，不是结果判断：\n\n"
                                + "① 正常无调试器/Frida 时，四路都应安全，翻页可取数；\n"
                                + "② 任一命中后密钥会被翻位，服务端静默 403；\n"
                                + "③ 绕法分两类：patch/hook 让哨兵不命中，或静态还原真标记\n"
                                + "   派生 HMAC 后绕开 so 直接取数；\n"
                                + "④ 真标记藏 UTF-16，明文诱饵一字之差。\n\n"
                                + "取证注意：真机关在 nativeSign，不是自检按钮。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));
        root.addView(Ui.banner(this, R.drawable.level_kkl3, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
        loadPage(1);
    }

    private void loadPage(final int page) {
        if (loading) return;
        loading = true;
        runOnUiThread(new Runnable() {
            @Override public void run() { status.setText("正在请求第 " + page + " 页…"); }
        });
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    final long ts = System.currentTimeMillis() / 1000;
                    final String sign = Kkl3Native.nativeSign(page, ts);
                    final String url = base + "/api/kkl3?page=" + page + "&ts=" + ts + "&sign=" + sign;
                    Request req = new Request.Builder().url(url)
                            .header("User-Agent", "Fatdog/1.0 (Android)")
                            .get().build();
                    Response resp = client.newCall(req).execute();
                    final int[] nums;
                    try {
                        if (!resp.isSuccessful()) {
                            throw new IllegalStateException("HTTP " + resp.code()
                                    + "（哨兵命中或标记用错，密钥可能已被投毒）");
                        }
                        JSONObject jo = new JSONObject(resp.body().string());
                        JSONArray arr = jo.getJSONArray("nums");
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
                                    + nums.length + " 个数（密钥正常）");
                        }
                    });
                } catch (final Throwable t) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            loading = false;
                            status.setText("请求失败: " + t + "\n可重试，也可「哨兵自检」看状态。");
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
}
