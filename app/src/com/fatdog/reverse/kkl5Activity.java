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

// 太玄之初 KKL5 · 诛仙台（★★★★★ 收官卷，服务端取数）。
// 这里的机关不是壳，是一台自造的虚拟机：它一步步把钥匙从标记里算出来，
// 指令密文按前一条自反馈加密——解得开第 N 条，才有第 N+1 条。
// 取数走两层加密复合（内层分组 + 外层流式）叠一层摘要签名；五个 so 缺一不可。
// 主钥只出 VM 的门，就立刻被拆成四层钥匙：三层壳（外层 y.* → 壳 A → 壳 B）
// 再加十三片业务 DEX，逐层解开；业务片里的取数方法是 native 的，得门面 so 显式绑定。
// 完整性守卫一旦命中，主钥被静默污染，服务端全程不给你报错。
public class kkl5Activity extends Activity {
    static final String SUM_HASH = "206125c6e7523ba7c0301144ac24eea9";
    static final int PAGES = 100;
    static final int PER_PAGE = 10;

    // 三级壳（外层 y.* + 壳 A + 壳 B）+ 13 片业务 DEX（5a..5m）的密文资源
    static final String OUTER_ASSET = "kkl5/outer_lock.bin";
    static final String SHELL_A_ASSET = "kkl5/shell_a_lock.bin";
    static final String SHELL_B_ASSET = "kkl5/shell_b_lock.bin";
    static final String[] BIZ_ASSETS = {
            "kkl5/5a_vein.bin", "kkl5/5b_vein.bin", "kkl5/5c_vein.bin",
            "kkl5/5d_vein.bin", "kkl5/5e_vein.bin", "kkl5/5f_vein.bin",
            "kkl5/5g_vein.bin", "kkl5/5h_vein.bin", "kkl5/5i_vein.bin",
            "kkl5/5j_vein.bin", "kkl5/5k_vein.bin", "kkl5/5l_vein.bin",
            "kkl5/5m_vein.bin"};
    static final String BIZ = "com.fatdog.reverse.kkl5.GateKeeper5";

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private EditText ansIn;
    private int currentPage = 1;
    private boolean loading = false;
    private boolean gateOk = false;
    private boolean ready = false;
    private String base;
    private OkHttpClient client;

    private Method mFetch;

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
            status.setText("onCreate 门禁通过，破塔解壳中…");
            bootBiz();
        } else {
            status.setText("门禁未通过：" + gate + "\nso 可能被 patch / 环境被 hook。");
        }
    }

    /** 后台：跑 VM 拿主钥 → 解三层壳（外层 y.* / 壳 A / 壳 B）→ 解 13 业务 DEX
     *  → 链式装载 → nativeBind → 反射缓存取数入口。 */
    private void bootBiz() {
        try {
            setStatus("破塔：过 VM 门禁、取钥匙…");
            // ① 外层壳（y.*）：layer 1
            byte[] outerDex = Kkl5Native.nativeFold(readAssetBytes(OUTER_ASSET), 1, 0);
            if (!isDex(outerDex)) throw new IllegalStateException("外层壳解出的不是 dex（VM 未过或钥匙错）");

            // ② 壳 DEX A：layer 2
            byte[] shellADex = Kkl5Native.nativeFold(readAssetBytes(SHELL_A_ASSET), 2, 0);
            if (!isDex(shellADex)) throw new IllegalStateException("壳 A 解出的不是 dex");

            // ③ 壳 DEX B：layer 3
            byte[] shellBDex = Kkl5Native.nativeFold(readAssetBytes(SHELL_B_ASSET), 3, 0);
            if (!isDex(shellBDex)) throw new IllegalStateException("壳 B 解出的不是 dex");

            // ④ 13 片业务 DEX：layer 4（shard 0..12）
            final byte[][] biz = new byte[13][];
            for (int i = 0; i < 13; i++) {
                biz[i] = Kkl5Native.nativeFold(readAssetBytes(BIZ_ASSETS[i]), 4, i);
                if (!isDex(biz[i])) {
                    throw new IllegalStateException("第 " + (i + 1) + " 片业务解出的不是 dex");
                }
            }
            setStatus("三层壳与十三片已解开，链式装载中…");

            // ⑤ 链式 InMemoryDexClassLoader：13 业务按序挂 parent（5a→…→5m），
            //    三层壳 loader 挂在业务链末端（壳是最外层，靠双亲委派往里找业务类）。
            ClassLoader cur = makeLoader(biz[0]);
            for (int i = 1; i < 13; i++) {
                cur = makeLoader(biz[i], cur);
            }
            ClassLoader shellBLoader = makeLoader(shellBDex, cur);
            ClassLoader shellALoader = makeLoader(shellADex, shellBLoader);
            ClassLoader outerLoader = makeLoader(outerDex, shellALoader);

            final Class<?> clsL = Class.forName("com.fatdog.reverse.kkl5.GateKeeper5l", true, cur);
            final Class<?> clsBiz = Class.forName(BIZ, true, cur);

            // ⑥ 壳类群职责核对（三级壳：外层 y.* → 壳 A → 壳 B，逐层 .class 常量串联）。
            final Class<?> clsOuter = Class.forName("com.fatdog.reverse.shelly.Wick", true, outerLoader);
            boolean outerOk = (Boolean) clsOuter.getMethod("sane", byte[].class).invoke(null, (Object) biz[0]);
            Class<?> next1 = (Class<?>) clsOuter.getMethod("nextClass").invoke(null);
            if (!outerOk || next1 == null) throw new IllegalStateException("外层壳职责不齐（可能误入诱饵）");

            Class<?> next2 = (Class<?>) next1.getMethod("nextClass").invoke(null);
            boolean aOk = (Boolean) next1.getMethod("sane", byte[].class).invoke(null, (Object) biz[1]);
            if (!aOk || next2 == null) throw new IllegalStateException("壳 A 职责不齐");

            boolean bOk = (Boolean) next2.getMethod("sane", byte[].class).invoke(null, (Object) biz[2]);
            Class<?> bindCls = (Class<?>) next2.getMethod("bindingClass").invoke(null);
            if (!bOk || bindCls != clsL) throw new IllegalStateException("壳 B 职责不齐（绑定目标错）");

            // ⑦ nativeBind：把业务片 GateKeeper5l.nativeSign 显式绑定
            int bound = Kkl5Native.nativeBind(clsL);
            if (bound != 1) throw new IllegalStateException("native 绑定失败（子加载器未解析父 so）");

            // ⑧ 缓存主编排取数入口
            mFetch = clsBiz.getMethod("fetch", int.class, long.class);
            String magic = (String) clsBiz.getMethod("magic").invoke(null);
            ready = true;
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("破塔成功：" + magic + "（三层壳 + 十三片已就位）— 可以翻页取数了");
                    Toast.makeText(kkl5Activity.this, "破塔成功，取数就绪", Toast.LENGTH_SHORT).show();
                }
            });
            loadPage(1);
        } catch (final Throwable t) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("破塔失败：" + t);
                    Toast.makeText(kkl5Activity.this, "失败：" + t.getMessage(), Toast.LENGTH_SHORT).show();
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
        java.io.File tmp = new java.io.File(getCacheDir(), "kkl5_shard_" + System.nanoTime() + ".dex");
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
        if (loading || !gateOk || !ready) return;
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
