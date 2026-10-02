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
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.InputStream;
import java.security.MessageDigest;

// 签名校验对抗第五课 · 幽冥合卷（收官综合卷，★★★★★）：
// 三点互验记账（Application 记账 → Activity 核账 → native 再核账互锁）
// + CRC 自校验基线 + certHash 参与 AES 密钥派生 + 响应 AES 加密。
// 任一环节缺失 → 静默投毒一字节。
public class w52Activity extends Activity {
    static final String SUM_HASH = "33aaee41697efda99ea79542e882d8b3d437cd85c196944e60fe6d408a3d1c77";
    static final int PAGES = 100;
    static final int PER_PAGE = 10;
    private static final int GUARD_TICK = 0xABCD;
    private static final int GUARD_RECHECK = 1;

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

        /* ====== 三点互验记账：启动记账 → 递入当前包证书 → 核账 ====== */
        Wp.nativeAudit();
        try {
            Wp.nativeSeed(getCertDer());   // ② 当前包证书摘要纳入守卫矩阵
        } catch (Throwable ignored) {
            // 取不到也照常走——守卫矩阵会判负，派生自动落到诱饵标记
        }

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(14), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("这一关的门被封死了——不拆开这个 App 就推不开。本关不欢迎动态注入，\n"
                + "请用「解包 → 改 → 重打包 → 重签名 → 安装」的方式进来。\n"
                + "进来之后还有第二重门：守卫矩阵（记账 / 核账 / 当前包证书摘要 / 基准数组 CRC）\n"
                + "四路同时在线，缺一即派生到诱饵标记——服务端喂给你的全是脏数据。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        status = new TextView(this);
        status.setText("准备中…");
        status.setGravity(Gravity.CENTER);
        status.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(status, Ui.wrap(8));

        /* ====== Activity 核账 + native 再核账（结论不弹提示，交给脏数据说话） ====== */
        Wp.nativeGuard(GUARD_TICK, GUARD_RECHECK);

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
                    else Toast.makeText(w52Activity.this, "页码超出范围 1-" + PAGES, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(w52Activity.this, "请输入页码", Toast.LENGTH_SHORT).show();
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
        // ① 第一层障碍（A）：推开门之前，提交按钮根本不出现
        subBtn.setVisibility(phaseOne() ? View.VISIBLE : View.GONE);

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(w52Activity.this)
                        .setTitle("提示")
                        .setMessage("本关是两层。第一层有两处门（都要解）：① libfelix.so 里一个纯开关常量——不拆包改它就取不到数；② 提交按钮在 smali 里被藏起来了。这一步只为逼你走一次「改包→重签→安装」，不是考点。\n"
                                + "第二层才是考点：守卫矩阵四路——启动记账(nativeAudit) / 核账(nativeGuard) / **当前包证书摘要 == 内置基准**(nativeSeed) / **基准数组 CRC32**(MARK_X‖DMARK_X‖BENCH_X)。\n"
                                + "四路全过 → key = SHA256(基准 ‖ \"Fatdog_seal\" ‖ vt)，服务端给真数据；\n"
                                + "任一不过 → key 改用诱饵标记 \"Fatdog_steal\" 派生 → 服务端回【脏数据】——数字看着完全正常，但求和不对，自己去排查。\n"
                                + "三条正解：① Frida spawn 抢跑伪造四路（含把 nativeSeed 的 DER 换成原包的）；② patch so 废 CRC 比较 + 派生标记比较；③ 重打包 + 完整复刻派生链（最硬核）。\n"
                                + "响应体是 AES-ECB 加密的 {\"d\": hex}，解出来是 \"page=N|nums=...\"。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(10));

        box.addView(Ui.banner(this, R.drawable.level_52, 150));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (SUM_HASH.isEmpty() || SUM_HASH.startsWith("待")) {
                    Toast.makeText(w52Activity.this, "本关尚在开发中", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (sha256Hex(ans).equals(SUM_HASH)) {
                    Celebration.show(w52Activity.this, "FLAG_18_L47{guard_matrix_crc_aes}");
                    PassLog.mark(w52Activity.this, "L47");
                } else {
                    Toast.makeText(w52Activity.this,
                            "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        loadPage(1);
    }

    // ① 第一层障碍 · A：提交按钮默认不出现。
    //    解包后把这里改成返回 true（按钮随之出现），再加上 so 里那个纯开关常量，重打包重签才能取数+提交。
    private boolean phaseOne() {
        return false;
    }

    private void loadPage(final int page) {
        if (loading) return;
        // ③ 先向 libfelix.so 要一次性令牌：① 门未开 → 空串 → 根本发不出请求
        final String vt = Wp.verdictToken();
        if (vt.isEmpty()) {
            loading = false;
            status.setText("取数被拒绝：本关的门被封死了，得先动手改这个 App 才能推开。");
            return;
        }
        loading = true;
        status.setText("正在请求第 " + page + " 页…");
        Zd.fetchPage(base, page, vt, new Zd.Cb() {
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
            return Zd.BASE;
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
