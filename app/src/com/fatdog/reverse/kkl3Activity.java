package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
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

import org.json.JSONObject;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

import dalvik.system.InMemoryDexClassLoader;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

// 太玄之初 KKL3 · 断魂谷：二代壳 · 多 DEX（双亲委派）+ 方法体抽取（★★★，服务端取数）。
// 业务拆五片（GateKeeper3a/3b/3c/3d/3e），构建期各片 SM4-ECB 加密埋 assets；
// 其中 3d.mixByte 与 3e.derive 的方法体被"抽取"——真实字节码搬进独立 bin，
// dex 里只剩空壳（nop; return-void），须先回填才能真正跑通。
// 五片经 InMemoryDexClassLoader 链式内存加载（3e.parent=3d=...=3a，多级双亲委派），
// 主钥由 3e.derive() 在 Java 侧派生，再交给 nativeSign 签名取数。
// 玩家需：① fartwithClassLoader 逐 Element 掏五片 ② 认抽取壳（空方法体）
// ③ 主动调用回填 ④ fart.py 修复 ⑤ 读 GateKeeper3 派生主钥 + 取数。
public class kkl3Activity extends Activity {
    static final String SUM_HASH = "e5b2b969f92ce208b531c252d9ccacc5";
    static final int PAGES = 100;
    static final String[] ASSETS = {
            "kkl3/edge_vein.bin", "kkl3/guard_vein.bin", "kkl3/grip_vein.bin",
            "kkl3/blade_vein.bin", "kkl3/hilt_vein.bin"};
    // 3d/3e 的抽取 bin（明文，须在回填时读）
    static final String[] EXTRACT_ASSETS = {null, null, null, "kkl3/3d_extract.bin", "kkl3/3e_extract.bin"};
    static final String BIZ_E = "com.fatdog.reverse.kkl3.GateKeeper3";

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private int currentPage = 1;
    private boolean ready = false;
    private boolean loading = false;
    private String base;
    private OkHttpClient client;

    private Class<?> biz;
    private Method mDerive;
    private byte[] seed;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        base = NetHost.httpBase();
        client = new OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(14), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KKL3 · 断魂谷（★★★）\n\n"
                + "谷底封着五片薄甲，首尾相扣，须层层剥开才能见底。\n"
                + "其中两片是残缺的——它俩的「芯」被抽走了，只剩空壳；\n"
                + "不把芯填回去，你走不到最后一步。\n"
                + "五片各自落在一把轮钥之下，形状相同、药引不同。\n\n"
                + "取满 100 页（每页 10 个数），求和后取摘要提交。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        status = new TextView(this);
        status.setText("尚未解开：点击「破谷」启动。");
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
        box.addView(grid, Ui.fullWidth(12));

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
                if (ready && currentPage > 1) loadPage(currentPage - 1);
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
                if (ready && currentPage < PAGES) loadPage(currentPage + 1);
            }
        });
        box.addView(navRow, Ui.fullWidth(10));

        Button scanBtn = new Button(this);
        scanBtn.setText("环境自检");
        Ui.styleButton(scanBtn);
        scanBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                status.setText(Kkl3Native.nativeStatus());
            }
        });
        box.addView(scanBtn, Ui.wrap(8));

        Button boot = new Button(this);
        boot.setText("破谷");
        Ui.styleButton(boot);
        boot.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (!loading) new Thread(new Runnable() {
                    @Override public void run() { bootBiz(); }
                }).start();
            }
        });
        box.addView(boot, Ui.wrap(10));

        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入总和 md5（32 位 hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        int pad = Ui.dp(10);
        ansIn.setPadding(pad, pad, pad, pad);
        box.addView(ansIn, Ui.fullWidth(10));

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
                    Toast.makeText(kkl3Activity.this, "摘要不对，先把 100 页都取回来。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(kkl3Activity.this)
                        .setTitle("提示")
                        .setMessage("断魂谷分析路线：\n\n"
                                + "① 五片薄甲都在 assets 里（形似而质不同，其中一件是假壳）；\n"
                                + "② 每片一把轮钥，药引按片不同——先还原轮钥的派生；\n"
                                + "③ 关键在「芯被抽走」的两片：反编译看到的只是空壳，\n"
                                + "    真实的那一段躺在旁边的 bin 里，须按位置填回去；\n"
                                + "④ 五片是串起来的（后片认前片），要按「逐层剥」的顺序装；\n"
                                + "⑤ 拿到第五片里的派生入口，算出 16 字节，再走国密 + 摘要取数。\n\n"
                                + "取证方向：逐片 dump 五片 dex，认「空方法体」的抽取壳，\n"
                                + "用主动调用触发回填，再把缺的那段补回，最后复刻派生链。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));
        box.addView(Ui.banner(this, R.drawable.level_kkl3, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
        loadPage(1);
    }

    /** 后台：读五片密文 → 各自解密 → 3d/3e 回填 → 链式内存装载 → 反射缓存业务类 */
    private void bootBiz() {
        try {
            setStatus("读取五片密文…");
            final byte[][] dex = new byte[5][];
            for (int i = 0; i < 5; i++) {
                byte[] enc = readAssetBytes(ASSETS[i]);
                dex[i] = Kkl3Native.nativeFold(enc, i);
                if (dex[i] == null || dex[i].length < 8
                        || !(dex[i][0] == 'd' && dex[i][1] == 'e' && dex[i][2] == 'x')) {
                    throw new IllegalStateException("第 " + (i + 1) + " 片解出的字节不是 dex，检查解密链");
                }
                // 3d/3e 回填（芯被抽走的两片）
                if (EXTRACT_ASSETS[i] != null) {
                    byte[] bin = readAssetBytes(EXTRACT_ASSETS[i]);
                    dex[i] = Kkl3Native.nativeRebind(dex[i], bin);
                    if (dex[i] == null) {
                        throw new IllegalStateException("第 " + (i + 1) + " 片回填失败，抽取 bin 不匹配");
                    }
                }
            }
            setStatus("五片就绪，链式内存装载中…");
            ClassLoader l1 = makeLoader(dex[0]);
            ClassLoader l2 = makeLoader(dex[1], l1);
            ClassLoader l3 = makeLoader(dex[2], l2);
            ClassLoader l4 = makeLoader(dex[3], l3);
            ClassLoader l5 = makeLoader(dex[4], l4);
            final Class<?> clsA = Class.forName("com.fatdog.reverse.kkl3.GateKeeper3a", true, l1);
            final Class<?> clsB = Class.forName("com.fatdog.reverse.kkl3.GateKeeper3b", true, l2);
            final Class<?> clsC = Class.forName("com.fatdog.reverse.kkl3.GateKeeper3c", true, l3);
            final Class<?> clsD = Class.forName("com.fatdog.reverse.kkl3.GateKeeper3d", true, l4);
            final Class<?> clsE = Class.forName(BIZ_E, true, l5);
            final String magic = (String) clsA.getMethod("magic").invoke(null);
            mDerive = clsE.getMethod("derive");
            seed = (byte[]) mDerive.invoke(null);
            if (seed == null || seed.length != 16) {
                throw new IllegalStateException("派生主钥形状不对（应 16 字节）");
            }
            biz = clsE;
            ready = true;
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("五片已装载：" + magic + "（主钥 16B）— 可以翻页取数了");
                    Toast.makeText(kkl3Activity.this, "五片装载成功", Toast.LENGTH_SHORT).show();
                }
            });
            loadPage(1);
        } catch (final Throwable t) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("启动失败：" + t);
                    Toast.makeText(kkl3Activity.this, "失败：" + t.getMessage(), Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    private ClassLoader makeLoader(byte[] dex) {
        return makeLoader(dex, getClassLoader());
    }

    private ClassLoader makeLoader(byte[] dex, ClassLoader parent) {
        if (Build.VERSION.SDK_INT >= 26) {
            return new InMemoryDexClassLoader(ByteBuffer.wrap(dex), parent);
        }
        java.io.File tmp = new java.io.File(getCacheDir(), "kkl3_shard_" + System.nanoTime() + ".dex");
        java.io.FileOutputStream fos;
        try {
            fos = new java.io.FileOutputStream(tmp);
            fos.write(dex);
            fos.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return new dalvik.system.DexClassLoader(tmp.getAbsolutePath(),
                getCacheDir().getAbsolutePath(), null, parent);
    }

    private void loadPage(final int page) {
        if (loading) return;
        loading = true;
        if (!ready) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    loading = false;
                    currentPage = 1;
                    status.setText("尚未解开：点击「破谷」后取数。");
                    renderNav(1);
                }
            });
            return;
        }
        runOnUiThread(new Runnable() {
            @Override public void run() { status.setText("正在请求第 " + page + " 页…"); }
        });
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    final long ts = System.currentTimeMillis() / 1000;
                    final String token = Kkl3Native.nativeSign(seed, page, ts);
                    final int bar = token == null ? -1 : token.indexOf('|');
                    if (bar <= 0) {
                        throw new IllegalStateException("取数内核未就绪或主钥已被污染");
                    }
                    final String enc = token.substring(0, bar);
                    final String sign = token.substring(bar + 1);
                    final String url = base + "/api/kkl3?page=" + page + "&ts=" + ts
                            + "&enc=" + enc + "&sign=" + sign;
                    Request req = new Request.Builder().url(url)
                            .header("User-Agent", "Fatdog/1.0 (Android)")
                            .get().build();
                    Response resp = client.newCall(req).execute();
                    final int[] nums;
                    try {
                        if (!resp.isSuccessful()) {
                            throw new IllegalStateException("HTTP " + resp.code()
                                    + "（门没开：主钥不对，或环境已被标记可疑）");
                        }
                        JSONObject jo = new JSONObject(resp.body().string());
                        org.json.JSONArray arr = jo.getJSONArray("nums");
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
                            status.setText("第 " + page + "/" + PAGES + " 页已取，" + nums.length + " 个数");
                        }
                    });
                } catch (final Throwable t) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            loading = false;
                            status.setText("请求失败: " + t + "（可重试）");
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
                    if (ready && fp != currentPage) loadPage(fp);
                }
            });
            pageBar.addView(chip, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        }
    }

    private byte[] readAssetBytes(String name) throws Exception {
        InputStream is = getAssets().open(name);
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        is.close();
        return bos.toByteArray();
    }

    private void setStatus(final String s) {
        runOnUiThread(new Runnable() {
            @Override public void run() { status.setText(s); }
        });
    }
}
