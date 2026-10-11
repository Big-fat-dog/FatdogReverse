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

import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

import dalvik.system.InMemoryDexClassLoader;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

// 太玄之初 KKL4 · 锁妖塔（★★★★，服务端取数）。
// 塔里没有「现成的壳」：它把"派生主钥"这件事搬进了一台自造的**栈式**虚拟机，
// 字节码还是一条压一条链式加密的——解得开第一条，才有第二条。
// 主钥只出 VM 的门，就立刻被拆成两把钥匙（壳层一把、业务九把），
// 分别去解「多类壳（w.* 一簇）」与九片业务 DEX；先过 VM，才有钥匙。
// 业务 DEX 里的取数方法是 native 的，得由门面 so 显式绑定才跑得起来。
public class kkl4Activity extends Activity {
    static final String SUM_HASH = "f39535a04e58cb747941d0e1dda62670";
    static final int PAGES = 100;
    static final int PER_PAGE = 10;

    // 壳层 DEX（w.* 类群）+ 九片业务 DEX（4a..4i）的密文资源
    static final String SHELL_ASSET = "kkl4/shell_lock.bin";
    static final String[] BIZ_ASSETS = {
            "kkl4/4a_vein.bin", "kkl4/4b_vein.bin", "kkl4/4c_vein.bin",
            "kkl4/4d_vein.bin", "kkl4/4e_vein.bin", "kkl4/4f_vein.bin",
            "kkl4/4g_vein.bin", "kkl4/4h_vein.bin", "kkl4/4i_vein.bin"};
    static final String BIZ = "com.fatdog.reverse.kkl4.GateKeeper4";

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private int currentPage = 1;
    private boolean ready = false;
    private boolean loading = false;
    private String base;
    private OkHttpClient client;

    private Method mFetch;

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
        tv.setText("KKL4 · 锁妖塔（★★★★）\n\n"
                + "塔锁的不是妖，是一把钥匙。\n"
                + "门后是一台自造的虚拟机：指令一条压一条地加密，\n"
                + "前一条解不开，后一条就是个谜；真正的钥匙从不出现在明文里。\n\n"
                + "钥匙出了 VM 的门，立刻拆成两把：一把开壳，一把开九片薄甲，\n"
                + "壳还是一簇散开的类，单看哪一片都拼不出全貌。\n\n"
                + "取满 100 页（每页 10 个数），求和后取摘要提交。");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        status = new TextView(this);
        status.setText("尚未破塔：点击「破塔」启动。可先点「环境自检」看门是否开着。");
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
                status.setText(Kkl4Native.nativeStatus());
            }
        });
        root.addView(scanBtn, Ui.wrap(10));

        Button boot = new Button(this);
        boot.setText("破塔");
        Ui.styleButton(boot);
        boot.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (!loading) new Thread(new Runnable() {
                    @Override public void run() { bootBiz(); }
                }).start();
            }
        });
        root.addView(boot, Ui.wrap(10));

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
                if (!loading && ready && currentPage > 1) loadPage(currentPage - 1);
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
                if (!loading && ready && currentPage < PAGES) loadPage(currentPage + 1);
            }
        });
        root.addView(navRow, Ui.fullWidth(10));

        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入总和 md5（32 位 hex）");
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
                    Toast.makeText(kkl4Activity.this, "请输入答案", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (ans.equalsIgnoreCase(SUM_HASH)) {
                    Celebration.show(kkl4Activity.this, "FLAG_18_KKL4{tower_of_the_sealed}");
                    PassLog.mark(kkl4Activity.this, "KKL4");
                } else {
                    Toast.makeText(kkl4Activity.this, "摘要不对，先把 100 页都取回来。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(kkl4Activity.this)
                        .setTitle("提示")
                        .setMessage("锁妖塔的钥匙从不出现在明文里：\n\n"
                                + "① lib/ 下五个 so 是一套编队，先摸清谁在算、谁在守；\n"
                                + "② 这台虚拟机的指令一条压一条地加密，\n"
                                + "   静态段里看不到钥匙，硬解也得按顺序来；\n"
                                + "③ 钥匙出 VM 门就拆成两把：一把开壳（一簇散开的类），\n"
                                + "   一把开九片薄甲——先过 VM，才有这两把钥匙；\n"
                                + "④ 业务片里的取数方法是 native 的，要门面 so 显式绑定才跑得起来；\n"
                                + "⑤ 两个标记一真一假，拼写只差一点，仔细比对。\n\n"
                                + "取证方向：FART 只能 dump 到外壳——先把壳这簇类认全、把 VM 的\n"
                                + "主钥派生复刻出来，再逐层解开九片，最后读取数入口复刻整条链。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));
        root.addView(Ui.banner(this, R.drawable.level_kkl4, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }

    /** 后台：跑 VM 拿主钥 → 解壳层 w.* → 解九片业务 DEX → 链式装载 → nativeBind → 反射缓存取数入口。 */
    private void bootBiz() {
        try {
            setStatus("破塔：过 VM 门禁、取钥匙…");
            // ① 壳层 DEX（w.* 类群）：layer 1
            byte[] shellDex = Kkl4Native.nativeFold(readAssetBytes(SHELL_ASSET), 1, 0);
            if (!isDex(shellDex)) throw new IllegalStateException("壳层解出的不是 dex（VM 未过或钥匙错）");

            // ② 九片业务 DEX：layer 2（shard 0..8）
            final byte[][] biz = new byte[9][];
            for (int i = 0; i < 9; i++) {
                biz[i] = Kkl4Native.nativeFold(readAssetBytes(BIZ_ASSETS[i]), 2, i);
                if (!isDex(biz[i])) {
                    throw new IllegalStateException("第 " + (i + 1) + " 片业务解出的不是 dex");
                }
            }
            setStatus("壳与九片已解开，链式装载中…");

            // ③ 链式 InMemoryDexClassLoader：九片业务按序挂 parent（4a→…→4i），
            //    壳层 loader 挂在业务链末端（壳是"最外层"，靠双亲委派往里找业务类）。
            ClassLoader cur = makeLoader(biz[0]);
            for (int i = 1; i < 9; i++) {
                cur = makeLoader(biz[i], cur);
            }
            ClassLoader shellLoader = makeLoader(shellDex, cur);
            final Class<?> clsH = Class.forName("com.fatdog.reverse.kkl4.GateKeeper4h", true, cur);
            final Class<?> clsBiz = Class.forName(BIZ, true, cur);

            // ④ 壳类群职责核对（多类壳：入料/解密/调度/回填各司其职）。
            //    入口 Wick 保留原名（r8_shell.pro keep），其余壳类已被 R8 改名——
            //    Wick 内部靠 .class 常量串联它们，R8 改名后仍自洽。
            final Class<?> clsWick = Class.forName("com.fatdog.reverse.shellw.Wick", true, shellLoader);
            boolean[] ready9 = new boolean[9];
            for (int i = 0; i < 9; i++) ready9[i] = true;
            Class<?> bindCls = (Class<?>) clsWick.getMethod(
                    "bindingClass", byte[].class, boolean[].class).invoke(null, (Object) biz[8], ready9);
            if (bindCls != clsH) {
                throw new IllegalStateException("壳类群职责不齐（可能误入诱饵壳）");
            }

            // ⑤ nativeBind：把业务片 GateKeeper4h.nativeSign 显式绑定
            int bound = Kkl4Native.nativeBind(clsH);
            if (bound != 1) {
                throw new IllegalStateException("native 绑定失败（子加载器未解析父 so）");
            }

            // ⑥ 缓存主编排取数入口
            mFetch = clsBiz.getMethod("fetch", int.class, long.class);
            String magic = (String) clsBiz.getMethod("magic").invoke(null);
            ready = true;
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("破塔成功：" + magic + "（九片 + 壳类群已就位）— 可以翻页取数了");
                    Toast.makeText(kkl4Activity.this, "破塔成功，取数就绪", Toast.LENGTH_SHORT).show();
                }
            });
            loadPage(1);
        } catch (final Throwable t) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("破塔失败：" + t);
                    Toast.makeText(kkl4Activity.this, "失败：" + t.getMessage(), Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    private static boolean isDex(byte[] b) {
        return b != null && b.length >= 8 && b[0] == 'd' && b[1] == 'e' && b[2] == 'x' && b[3] == '\n';
    }

    private byte[] readAssetBytes(String path) {
        try {
            InputStream is = getAssets().open(path);
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            is.close();
            return bos.toByteArray();
        } catch (java.io.IOException e) {
            throw new IllegalStateException("读资源失败：" + path, e);
        }
    }

    private ClassLoader makeLoader(byte[] dex) {
        return makeLoader(dex, getClassLoader());
    }

    private ClassLoader makeLoader(byte[] dex, ClassLoader parent) {
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            return new InMemoryDexClassLoader(ByteBuffer.wrap(dex), parent);
        }
        java.io.File tmp = new java.io.File(getCacheDir(), "kkl4_shard_" + System.nanoTime() + ".dex");
        try {
            java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp);
            fos.write(dex);
            fos.close();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
        return new dalvik.system.DexClassLoader(tmp.getAbsolutePath(),
                getCacheDir().getAbsolutePath(), null, parent);
    }

    private void setStatus(final String s) {
        runOnUiThread(new Runnable() {
            @Override public void run() { status.setText(s); }
        });
    }

    private void loadPage(final int page) {
        if (loading || !ready) return;
        loading = true;
        runOnUiThread(new Runnable() {
            @Override public void run() { status.setText("正在请求第 " + page + " 页…"); }
        });
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    final long ts = System.currentTimeMillis() / 1000;
                    final String token = (String) mFetch.invoke(null, page, ts);
                    final int bar = token == null ? -1 : token.indexOf('|');
                    if (bar <= 0) {
                        throw new IllegalStateException("取数内核未就绪（五 so 缺一或主钥已被污染）");
                    }
                    final String enc = token.substring(0, bar);
                    final String sign = token.substring(bar + 1);
                    final String url = base + "/api/kkl4?page=" + page + "&ts=" + ts
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
}
