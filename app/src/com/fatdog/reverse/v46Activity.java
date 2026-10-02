package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.InputStream;
import java.security.MessageDigest;

// 签名校验对抗第四课 · 以签为钥（L4 派生型主打）：
// key = SHA256(certDER ‖ "Fatdog_bind")，直接 HMAC-SHA256 整个表单。
// 没有 if 判断签名对错——重打包者的证书不同→派生 key 不同→服务端全部 403 零提示。
// 正解：运行时偷出 App 自己算的真实 certHash，离线复刻整条链取数。
public class v46Activity extends Activity {
    static final String SUM_HASH = "2227606ab8e049608fb66ca7c3ef80bf2e5316d6029fedf31627187e6af0dcca";
    static final int PAGES = 100;
    static final int PER_PAGE = 10;

    private TextView status;
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
        tv.setText("这一关的门被封死了——不拆开这个 App 就推不开。本关不欢迎动态注入，\n"
                + "请用「解包 → 改 → 重打包 → 重签名 → 安装」的方式进来。\n"
                + "进来之后还有第二重门：证书摘要派生密钥 key = SHA256(certHash ‖ 标记 ‖ vt)。\n"
                + "没有 if 判断——重打包者证书不同→派生 key 不同→服务端喂给你的全是脏数据。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

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
                    else Toast.makeText(v46Activity.this, "页码超出范围 1-" + PAGES, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(v46Activity.this, "请输入页码", Toast.LENGTH_SHORT).show();
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
                new AlertDialog.Builder(v46Activity.this)
                        .setTitle("提示")
                        .setMessage("本关是两层。第一层只是 libamber.so 里一个纯开关常量（g_door）——不拆包改它就取不到数；这一步只为逼你走一次「改包→重签→安装」，不是考点。\n"
                                + "第二层才是考点，且本关没有 if 判断签名对错：key = SHA256(certHash ‖ 标记 ‖ vt)，标记由「当前包证书摘要是否等于内置基准」决定。\n"
                                + "重打包后派生落到诱饵标记 → 服务端回【脏数据】——数字看着完全正常，但求和不对，自己去排查哪里出了问题。\n"
                                + "三条正解：① Frida hook Wg.nativeKeySeed 把 DER 换成原包的（或整体替换派生结果）；② unidbg 调 JNI 派生函数拿 32 字节 key；③ IDA 还原 amber 的 BENCH_X → XOR 0x66 还原 SHA-256 → Python 复刻派生链。\n"
                                + "服务端 POST /api/l46 表单字段：page / ts / nonce / vt / sign（被签串 nonce=<n>&page=<p>&ts=<t>，字典序）。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(10));

        box.addView(Ui.banner(this, R.drawable.level_51, 150));

        // ② 递入当前包的证书 DER：native 内摘要 + 与内置基准比对，
        //    结论决定派生密钥走真标记（Fatdog_bind）还是诱饵标记（Fatdog_band）
        try {
            Wg.nativeKeySeed(getCertDer());
        } catch (Throwable ignored) {
            // 取不到也照常走——派生会落到诱饵分支，只能取到脏数据
        }

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (sha256Hex(ans).equals(SUM_HASH)) {
                    Celebration.show(v46Activity.this, "FLAG_18_L46{key_derived_from_cert}");
                    PassLog.mark(v46Activity.this, "L46");
                } else {
                    Toast.makeText(v46Activity.this,
                            "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        loadPage(1);
    }

    private void loadPage(final int page) {
        if (loading) return;
        // ③ 先向 libamber.so 要一次性令牌：① 门未开 → 空串 → 根本发不出请求
        final String vt = Wg.verdictToken();
        if (vt.isEmpty()) {
            loading = false;
            status.setText("取数被拒绝：本关的门被封死了，得先动手改这个 App 才能推开。");
            return;
        }
        loading = true;
        status.setText("正在请求第 " + page + " 页…");
        Zc.fetchPage(base, page, vt, new Zc.Cb() {
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
                        status.setText("已加载第 " + got + " / " + PAGES + " 页，本页 " + nums.length + " 个数字");
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

    private byte[] getCertDer() throws Exception {
        android.content.pm.PackageInfo pi;
        if (android.os.Build.VERSION.SDK_INT >= 28) {
            pi = getPackageManager().getPackageInfo(getPackageName(),
                    android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES);
            android.content.pm.SigningInfo info = pi.signingInfo;
            return (info.hasMultipleSigners()
                    ? info.getApkContentsSigners()
                    : info.getSigningCertificateHistory())[0].toByteArray();
        } else {
            @SuppressWarnings("deprecation")
            android.content.pm.PackageInfo old = getPackageManager().getPackageInfo(
                    getPackageName(), android.content.pm.PackageManager.GET_SIGNATURES);
            return old.signatures[0].toByteArray();
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
            return Zc.BASE;
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
