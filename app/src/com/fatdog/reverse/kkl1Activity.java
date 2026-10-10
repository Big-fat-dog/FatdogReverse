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

import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;

import dalvik.system.DexClassLoader;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

// 太玄之初 KKL1 · 玄冥渊：DEX 整体加密 + 落盘加载（★，服务端取数）。
// 业务 DEX（com.fatdog.reverse.kkl1.GateKeeper1）构建期整体加密后埋进
// assets/kkl1/abyss_vein.bin（base64(rc4(dex))）；libkkl1.so 静态导出两个 native：
//   nativeUnseal(enc)    → 解密出明文 dex 字节
//   nativeDeriveSeal()    → 取数签名 seal（真标记藏 UTF-16 派生）
// 解密出的 dex 会落盘到沙箱目录，再交给 DexClassLoader 加载——这是本关设定
// 的「一代壳破绽」：会落地的壳，文件可被找到。取数逻辑只在加载出的 dex 里：
// GateKeeper1.sign(seal, ts, page) 逐页取数。
// 玩家需要：①（动态）在解密出口抓明文 dex /（静态）认 vtable 还原 mask + seal
// ② 拿 seal → ③ 逐页签名取数 → ④ 求和对总和取 md5。
public class kkl1Activity extends Activity {
    static final String SUM_HASH = "d22ace3cfb8d585d7d667394ecef4e6c";
    static final int PAGES = 100;
    static final String ASSET = "kkl1/abyss_vein.bin";
    static final String BIZ_CLASS = "com.fatdog.reverse.kkl1.GateKeeper1";

    private TextView status;
    private final TextView[] cells = new TextView[10];
    private LinearLayout pageBar;
    private int currentPage = 1;
    private boolean ready = false;      // dex 是否已解密并加载
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
                + "业务 DEX 被整体加密埋在 assets（base64 + RC4）。\n"
                + "libkkl1.so 静态导出两个方法：nativeUnseal 解 dex、nativeDeriveSeal 给签名 seal。\n"
                + "解出的 dex 会落到沙箱目录，再由 DexClassLoader 加载——会落地的壳，文件找得到。\n"
                + "取数签名逻辑只在加载出的 dex 里，100 页 × 每页 10 个数求和。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(4));

        status = new TextView(this);
        status.setText("未解密：点击「解密并加载」启动。");
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
        boot.setText("解密并加载业务 DEX");
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
                        .setMessage("玄冥渊分析路线：\n\n"
                                + "① 壳形状：assets/kkl1/abyss_vein.bin 是一段很长的文本——\n"
                                + "    拿去 base64 解码再想下一步（base64 不是加密）；\n"
                                + "② so：libkkl1.so 符号表直白可见，两个 native 一目了然；\n"
                                + "    解密链 = C++ 虚表分发的「掩码」⊕ 真标记派生的 seal → RC4 钥；\n"
                                + "    真标记以 UTF-16 码元藏在 .data（普通 strings 哑火）；\n"
                                + "③ dex 落盘：解密出的 dex 会写进沙箱目录再加载，会落地的壳\n"
                                + "    就是会被找到——去自己的沙箱里找找看；\n"
                                + "④ 取数：拿 seal（nativeDeriveSeal 或按真标记自己拼）→ 逐页签名\n"
                                + "    取 100 页 → 求和 → 对总和取 md5 就是答案。\n\n"
                                + "两个标记只有一处拼写差异，哪一个是真身得自己判断。")
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

    /** 后台线程：读 assets 密文 → nativeUnseal 解密 → 落盘 → DexClassLoader → 反射缓存 */
    private void bootBiz() {
        try {
            setStatus("读取 assets 密文…");
            byte[] enc = readAssetBytes(ASSET);
            setStatus("nativeUnseal 解密中…");
            final byte[] dex = Kkl1Native.nativeUnseal(enc);
            if (dex == null || dex.length < 8 || !(dex[0] == 'd' && dex[1] == 'e' && dex[2] == 'x')) {
                throw new IllegalStateException("解出的字节不是 dex（magic 不符），检查解密链");
            }
            setStatus("dex 就绪 " + dex.length + " B，落盘并加载…");
            // 落盘：一代壳的经典破绽——解密后的 dex 会留在沙箱目录里
            java.io.File dir = getDir("kkl1", MODE_PRIVATE);
            java.io.File dexFile = new java.io.File(dir, "vein_biz.dex");
            java.io.FileOutputStream fos = new java.io.FileOutputStream(dexFile);
            fos.write(dex);
            fos.close();
            java.io.File optDir = getDir("kkl1_opt", MODE_PRIVATE);
            ClassLoader loader = new DexClassLoader(dexFile.getAbsolutePath(),
                    optDir.getAbsolutePath(), null, getClassLoader());
            Class<?> cls = Class.forName(BIZ_CLASS, true, loader);
            final String magic = (String) cls.getMethod("magic").invoke(null);
            mSign = cls.getMethod("sign", byte[].class, long.class, int.class);
            seal = Kkl1Native.nativeDeriveSeal();
            if (seal == null || seal.length != 16) {
                throw new IllegalStateException("派生 seal 形状不对（应 16 字节）");
            }
            ready = true;
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("业务类已加载：" + magic + "（seal 16B）— 可以翻页取数了");
                    Toast.makeText(kkl1Activity.this, "DEX 落盘加载成功", Toast.LENGTH_SHORT).show();
                }
            });
            loadPage(1);
        } catch (final Throwable t) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    status.setText("启动失败：" + t);
                    Toast.makeText(kkl1Activity.this, "失败：" + t.getMessage(), Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    private void loadPage(final int page) {
        if (loading) return;
        loading = true;
        if (!ready) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    loading = false;
                    currentPage = 1;
                    status.setText("未解密：点击「解密并加载」后取数。");
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
