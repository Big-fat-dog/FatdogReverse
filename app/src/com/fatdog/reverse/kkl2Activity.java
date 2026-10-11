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

// 太玄之初 KKL2 · 万剑冢：二代壳 · DEX 整体加密 + 内存加载不落盘（★★，服务端取数）。
// 业务 DEX 拆三片（com.fatdog.reverse.kkl2.GateKeeper2a/2b/2c），构建期各自 AES-128-CBC
// 整体加密后埋进 assets/kkl2/{edge,guard,grip}_vein.bin；libkkl2.so 动态注册两个 native：
//   nativeFold(enc, shard) → 按片号解密出明文 dex 字节
//   nativeSeed()           → 取数签名 seal（真标记藏 UTF-16，MD5 派生）
// 三片明文 dex 经 InMemoryDexClassLoader 链式内存加载（2c.parent=2b、2b.parent=2a，不落盘），
// 取数逻辑只在加载出的第三片里：GateKeeper2c.sign(seal, ts, page) 签 MD5 逐页取数。
// 玩家需要：① 认 assets 假壳 classes_decoy.dex → ② 还原解密链 / hook nativeFold
// ③ dump 出三片 dex → ④ 拿 seal → ⑤ MD5 取 100 页求和。
public class kkl2Activity extends Activity {
    static final String SUM_HASH = "f2137159e2a60cd3abc4a35309aa1839";
    static final int PAGES = 100;
    static final String[] ASSETS = {"kkl2/edge_vein.bin", "kkl2/guard_vein.bin", "kkl2/grip_vein.bin"};
    static final String BIZ_A = "com.fatdog.reverse.kkl2.GateKeeper2a";
    static final String BIZ_B = "com.fatdog.reverse.kkl2.GateKeeper2b";
    static final String BIZ_C = "com.fatdog.reverse.kkl2.GateKeeper2c";

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private int currentPage = 1;
    private boolean ready = false;      // 三片 dex 是否已解密并内存加载
    private boolean loading = false;
    private String base;
    private OkHttpClient client;

    // 内存加载后的业务类（反射句柄缓存）
    private Class<?> biz;
    private Method mSign;
    private byte[] seal;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
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
        tv.setText("KKL2 · 万剑冢（★★）\n\n"
                + "渊底封着三片薄甲，各自藏着一层因果，彼此相扣、缺一不可。\n"
                + "它们不落地，只在虚空中显形；能看见它们全貌的地方，\n"
                + "既不在盘上，也不在字面里。\n"
                + "第三片里藏着一道取数的门，100 页 × 每页 10 个数求和。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        status = new TextView(this);
        status.setText("尚未解开：点击「解甲」启动。");
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

        // 分页导航
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

        // 解密 + 内存加载
        Button boot = new Button(this);
        boot.setText("解甲");
        Ui.styleButton(boot);
        boot.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (!loading) new Thread(new Runnable() {
                    @Override public void run() { bootBiz(); }
                }).start();
            }
        });
        box.addView(boot, Ui.wrap(10));

        // 答案输入 + 提交
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
                    Toast.makeText(kkl2Activity.this, "请输入答案", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (ans.equalsIgnoreCase(SUM_HASH)) {
                    Celebration.show(kkl2Activity.this, "FLAG_18_KKL2{tomb_of_myriad_blades}");
                    PassLog.mark(kkl2Activity.this, "KKL2");
                } else {
                    Toast.makeText(kkl2Activity.this, "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(subBtn, Ui.wrap(10));

        // 提示
        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(kkl2Activity.this)
                        .setTitle("提示")
                        .setMessage("万剑冢分析路线：\n\n"
                                + "① 先分真假：assets 里有一件是假的（形似而质空），\n"
                                + "    真正的三片薄甲是二进制密文（长度是 16 的倍数）；\n"
                                + "② 看装载：so 导出表很干净，两个入口是运行时才挂牌的；\n"
                                + "    解开薄甲要走「三段因果」——先还原一把轮钥与一缕冷雾，\n"
                                + "    再去掉尾部的补丁，最后按镜像位两两归位；\n"
                                + "③ 认标记：字面里躺着的那串只是幌子，真正的标记以\n"
                                + "    另一种编码藏在数据段（普通翻找看不到）；\n"
                                + "④ 抓三片：它们不落地，只能从虚空中掏——在「解完、装进」\n"
                                + "    那一瞬出手，或逐片把明文字节写回再细看；\n"
                                + "⑤ 取数：拿到第三片里的门 + 派生的印，逐页取 100 页求和。\n\n"
                                + "最短路线：在入口出口各下一钩，把三片明文都倒出来，\n"
                                + "签名照抄即可取数。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));
        box.addView(Ui.banner(this, R.drawable.level_kkl2, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
        loadPage(1);  // 进入即展示第一页（未就绪时提示）
    }

    /** 后台线程：读三片密文 → 各自 nativeFold 解密 → 链式内存加载 → 反射缓存业务类 */
    private void bootBiz() {
        try {
            setStatus("读取三片密文…");
            final byte[][] dex = new byte[3][];
            for (int i = 0; i < 3; i++) {
                byte[] enc = readAssetBytes(ASSETS[i]);
                dex[i] = Kkl2Native.nativeFold(enc, i);
                if (dex[i] == null || dex[i].length < 8
                        || !(dex[i][0] == 'd' && dex[i][1] == 'e' && dex[i][2] == 'x')) {
                    throw new IllegalStateException("第 " + (i + 1) + " 片解出的字节不是 dex（magic 不符），检查解密链");
                }
            }
            setStatus("三片就绪，链式内存装载中…");
            final ClassLoader l1 = makeLoader(dex[0]);
            final ClassLoader l2 = makeLoader(dex[1], l1);
            final ClassLoader l3 = makeLoader(dex[2], l2);
            final Class<?> clsA = Class.forName(BIZ_A, true, l1);
            final Class<?> clsB = Class.forName(BIZ_B, true, l2);
            final Class<?> clsC = Class.forName(BIZ_C, true, l3);
            final String magic = (String) clsA.getMethod("magic").invoke(null);
            final Object ok = clsB.getMethod("markLooksValid", byte[].class)
                    .invoke(null, new Object[]{new byte[16]});
            mSign = clsC.getMethod("sign", byte[].class, long.class, int.class);
            seal = Kkl2Native.nativeSeed();
            if (seal == null || seal.length != 16) {
                throw new IllegalStateException("派生印形状不对（应 16 字节）");
            }
            biz = clsC;
            ready = true;
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("三片已装载：" + magic + "（印 16B）— 可以翻页取数了");
                    Toast.makeText(kkl2Activity.this, "三片内存装载成功", Toast.LENGTH_SHORT).show();
                }
            });
            loadPage(1);
        } catch (final Throwable t) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("启动失败：" + t);
                    Toast.makeText(kkl2Activity.this, "失败：" + t.getMessage(), Toast.LENGTH_SHORT).show();
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
        // API 21-25 降级：落盘临时文件（教学提示——低版本 Android 没有 InMemoryDexClassLoader）
        java.io.File tmp = new java.io.File(getCacheDir(), "kkl2_shard_" + System.nanoTime() + ".dex");
        java.io.FileOutputStream fos;
        try {
            fos = new java.io.FileOutputStream(tmp);
            fos.write(dex);
            fos.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        runOnUiThread(new Runnable() {
            @Override public void run() {
                Toast.makeText(kkl2Activity.this,
                        "本机 API<26，内存装载不可用，已降级落盘。",
                        Toast.LENGTH_LONG).show();
            }
        });
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
                    status.setText("尚未解开：点击「解甲」后取数。");
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
                    final String sign = (String) mSign.invoke(null, seal, ts, page);
                    final String url = base + "/api/kkl2?page=" + page + "&ts=" + ts + "&sign=" + sign;
                    Request req = new Request.Builder().url(url)
                            .header("User-Agent", "Fatdog/1.0 (Android)")
                            .get().build();
                    Response resp = client.newCall(req).execute();
                    final int[] nums;
                    try {
                        if (!resp.isSuccessful()) {
                            throw new IllegalStateException("HTTP " + resp.code());
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
