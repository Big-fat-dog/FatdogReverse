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

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;

import dalvik.system.DexClassLoader;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

// 太玄之初 KKL1 · 玄冥渊：一代壳 · 业务拆两片（各整体加密）+ 落盘加载（★，服务端取数）。
// 业务拆成两片（GateKeeper1a / GateKeeper1b）：构建期分别整体加密成
// assets/kkl1/abyss_vein.bin、assets/kkl1/abyss_marrow.bin；另有明文诱饵
// assets/kkl1/classes_decoy.dex。
// libkkl1.so 动态注册两个 native（导出表无 Java_ 符号）：
//   nativeFold(enc)   → 还原一段加密分片 → 明文 dex 字节
//   nativeSeed()      → 取数签名用的 mark（真标记藏 UTF-16 派生）
// 两片各自落盘，再按序挂载（loader1b.parent = loader1a）：这是本关设定的
// 「一代壳破绽」——会落地的壳，文件找得到。
// 取数逻辑在第二片里：GateKeeper1b.sign(mark, ts, page) 逐页取数。
// 玩家需要：①（动态）在还原出口抓明文 dex（两片）/（静态）认虚表还原掩码 + mark
// ② 拿 mark → ③ 逐页签名取数 → ④ 求和对总和取 md5。
public class kkl1Activity extends Activity {
    static final String SUM_HASH = "d22ace3cfb8d585d7d667394ecef4e6c";
    static final int PAGES = 100;
    static final String ASSET_A = "kkl1/abyss_vein.bin";
    static final String ASSET_B = "kkl1/abyss_marrow.bin";
    static final String ASSET_DECOY = "kkl1/classes_decoy.dex";
    static final String BIZ_A = "com.fatdog.reverse.kkl1.GateKeeper1a";
    static final String BIZ_B = "com.fatdog.reverse.kkl1.GateKeeper1b";

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private int currentPage = 1;
    private boolean ready = false;      // 分片是否已还原并挂载
    private boolean loading = false;
    private String base;
    private OkHttpClient client;

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
        tv.setText("KKL1 · 玄冥渊（★）\n\n"
                + "渊底裹着一层薄壳，壳里不是一具真身，是拆开的两片。\n"
                + "它藏得不深——最古老的那种掩眼法，破绽不在进不去，在它会落下痕迹。\n"
                + "取数一页十枚，百页成数；签在真身手里，钥藏在翻不到字面的地方。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        status = new TextView(this);
        status.setText("未开壳：点击「破壳并挂载」启动。");
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

        Button boot = new Button(this);
        boot.setText("破壳并挂载");
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
                    Toast.makeText(kkl1Activity.this, "请输入答案", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (ans.equalsIgnoreCase(SUM_HASH)) {
                    Celebration.show(kkl1Activity.this, "FLAG_18_KKL1{abyss_of_mystery}");
                    PassLog.mark(kkl1Activity.this, "KKL1");
                } else {
                    Toast.makeText(kkl1Activity.this, "加和不对，再取数算一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        box.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(kkl1Activity.this)
                        .setTitle("提示")
                        .setMessage("玄冥渊探路：\n\n"
                                + "① 壳会卸货：它把真身写到自己的地盘上再挂起来——落地的壳，\n"
                                + "    就是会被找到的壳。别只盯着包里，也看看应用自己的目录。\n"
                                + "② 真身是两片，分先后挂载，后一片认前一片作长辈（双亲委派）。\n"
                                + "③ 两片长相平平无奇，符号表里也翻不到门道——换条路。\n"
                                + "    门在『钥』上：同一串字里藏着一处伪笔，差一个字母，\n"
                                + "    拼出的钥就全错（服务端只认一种拼法）。\n"
                                + "④ 拿到真钥 → 逐页签取 100 页 → 求和 → 对总和取 md5 就是答案。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));
        box.addView(Ui.banner(this, R.drawable.level_kkl1, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
        loadPage(1);
    }

    /** 后台线程：逐片还原加密分片 → 落盘 → 按序挂载（父链）→ 反射缓存取数签名 */
    private void bootBiz() {
        try {
            File dir = getDir("kkl1", MODE_PRIVATE);
            File optDir = getDir("kkl1_opt", MODE_PRIVATE);

            setStatus("还原分片一…");
            File fileA = new File(dir, "vein_a.dex");
            writeFile(fileA, restoreDex(ASSET_A));
            ClassLoader loaderA = new DexClassLoader(fileA.getAbsolutePath(),
                    optDir.getAbsolutePath(), null, getClassLoader());

            setStatus("还原分片二…");
            File fileB = new File(dir, "vein_b.dex");
            writeFile(fileB, restoreDex(ASSET_B));
            // 后一片认前一片作长辈：双亲委派链
            ClassLoader loaderB = new DexClassLoader(fileB.getAbsolutePath(),
                    optDir.getAbsolutePath(), null, loaderA);

            // 明文诱饵：一并落到同目录（不挂载）——落在盘上的东西，谁都能翻
            try {
                writeFile(new File(dir, "vein_x.dex"), readAssetBytes(ASSET_DECOY));
            } catch (Throwable ignore) {
                // 诱饵缺失不影响通关
            }

            setStatus("挂载真身…");
            Class<?> clsA = Class.forName(BIZ_A, true, loaderA);
            Class<?> clsB = Class.forName(BIZ_B, true, loaderB);
            final String tag = (String) clsA.getMethod("magic").invoke(null);
            mSign = clsB.getMethod("sign", byte[].class, long.class, int.class);
            seal = Kkl1Native.nativeSeed();
            if (seal == null || seal.length != 16) {
                throw new IllegalStateException("取到的钥形状不对（应 16 字节）");
            }
            ready = true;
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("真身已挂载：" + tag + "（钥 16B）— 可以翻页取数了");
                    Toast.makeText(kkl1Activity.this, "真身已挂载", Toast.LENGTH_SHORT).show();
                }
            });
            loadPage(1);
        } catch (final Throwable t) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("开壳失败：" + t);
                    Toast.makeText(kkl1Activity.this, "失败：" + t.getMessage(), Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    /** 读一段加密分片 → 还原 → 校验 dex 形状 */
    private byte[] restoreDex(String asset) throws Exception {
        byte[] enc = readAssetBytes(asset);
        byte[] dex = Kkl1Native.nativeFold(enc);
        if (dex == null || dex.length < 8
                || !(dex[0] == 'd' && dex[1] == 'e' && dex[2] == 'x')) {
            throw new IllegalStateException("分片还原失败（magic 不符）：" + asset);
        }
        return dex;
    }

    private void loadPage(final int page) {
        if (loading) return;
        loading = true;
        if (!ready) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    loading = false;
                    currentPage = 1;
                    status.setText("未开壳：点击「破壳并挂载」后取数。");
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
                    final String url = base + "/api/kkl1?page=" + page + "&ts=" + ts + "&sign=" + sign;
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
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        is.close();
        return bos.toByteArray();
    }

    private void writeFile(File f, byte[] data) throws Exception {
        FileOutputStream fos = new FileOutputStream(f);
        try {
            fos.write(data);
        } finally {
            fos.close();
        }
    }

    private void setStatus(final String s) {
        runOnUiThread(new Runnable() {
            @Override public void run() { status.setText(s); }
        });
    }
}
