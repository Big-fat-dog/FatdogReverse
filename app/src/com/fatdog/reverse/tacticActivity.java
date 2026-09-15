package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * KL41 纸上谈兵（须弥界 · JS Bundle 基础）
 *
 * 考点：JS bundle 中密钥拆分 + metro 混淆还原 + HMAC-SHA256 签名
 */
public class tacticActivity extends Activity {

    private static final int PAGES = 100;
    private static final int PER_PAGE = 10;
    private final int[][] allNums = new int[PAGES][PER_PAGE];
    private final boolean[] fetched = new boolean[PAGES];
    private int currentPage = 0;
    private int totalSum = 0;
    private int fetchedCount = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("须弥界 KL41 · 纸上谈兵（★）\n\n" +
                "竹简上残留着 bundle 的碎片，密钥被拆散藏于字符串迷宫之中。\n" +
                "签名在 JS 引擎深处计算，唯有还原混淆方能窥见真面目。\n\n" +
                "逐页取回数字，求和后提交答案。");
        tv.setTextSize(14);
        tv.setTextColor(Color.WHITE);
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        final TextView statusTv = new TextView(this);
        statusTv.setText("就绪 · 已取 0/" + PAGES + " 页");
        statusTv.setTextSize(12);
        statusTv.setTextColor(Color.LTGRAY);
        statusTv.setTypeface(Typeface.MONOSPACE);
        root.addView(statusTv, Ui.fullWidth(6));

        final TextView numGrid = new TextView(this);
        numGrid.setText("点击「取当前页」获取数字");
        numGrid.setTextSize(12);
        numGrid.setTextColor(Color.WHITE);
        numGrid.setTypeface(Typeface.MONOSPACE);
        numGrid.setBackgroundColor(0x22FFFFFF);
        numGrid.setPadding(Ui.dp(8), Ui.dp(8), Ui.dp(8), Ui.dp(8));
        root.addView(numGrid, Ui.fullWidth(6));

        // 页码导航
        LinearLayout nav = new LinearLayout(this);
        nav.setOrientation(LinearLayout.HORIZONTAL);
        nav.setGravity(Gravity.CENTER);
        Button prevBtn = new Button(this);
        prevBtn.setText("◀ 上一页");
        Ui.styleButton(prevBtn);
        prevBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (currentPage > 0) { currentPage--; refreshPage(statusTv, numGrid); }
            }
        });
        nav.addView(prevBtn, Ui.wrap(6));

        final TextView pageTv = new TextView(this);
        pageTv.setText(" 1 / " + PAGES + " ");
        pageTv.setTextSize(14);
        pageTv.setTextColor(Color.WHITE);
        pageTv.setTypeface(Typeface.MONOSPACE);
        pageTv.setGravity(Gravity.CENTER);
        nav.addView(pageTv, Ui.wrap(2));

        Button nextBtn = new Button(this);
        nextBtn.setText("下一页 ▶");
        Ui.styleButton(nextBtn);
        nextBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (currentPage < PAGES - 1) { currentPage++; refreshPage(statusTv, numGrid); }
            }
        });
        nav.addView(nextBtn, Ui.wrap(6));
        root.addView(nav, Ui.wrap(6));

        // 跳转
        LinearLayout jumpRow = new LinearLayout(this);
        jumpRow.setOrientation(LinearLayout.HORIZONTAL);
        jumpRow.setGravity(Gravity.CENTER);
        final EditText jumpIn = new EditText(this);
        jumpIn.setHint("页码");
        jumpIn.setTextColor(Color.WHITE);
        jumpIn.setTypeface(Typeface.MONOSPACE);
        jumpIn.setBackgroundColor(0x33FFFFFF);
        jumpIn.setGravity(Gravity.CENTER);
        jumpRow.addView(jumpIn, new LinearLayout.LayoutParams(Ui.dp(80), LinearLayout.LayoutParams.WRAP_CONTENT));
        Button jumpBtn = new Button(this);
        jumpBtn.setText("跳转");
        Ui.styleButton(jumpBtn);
        jumpBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                try {
                    int p = Integer.parseInt(jumpIn.getText().toString().trim());
                    if (p >= 1 && p <= PAGES) { currentPage = p - 1; refreshPage(statusTv, numGrid); }
                } catch (NumberFormatException ignored) {}
            }
        });
        jumpRow.addView(jumpBtn, Ui.wrap(6));
        root.addView(jumpRow, Ui.wrap(8));

        // 取当前页
        Button fetchBtn = new Button(this);
        fetchBtn.setText("取当前页");
        Ui.styleButton(fetchBtn);
        fetchBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                fetchPage(currentPage, statusTv, numGrid);
            }
        });
        root.addView(fetchBtn, Ui.wrap(10));

        // 一键全取
        Button fetchAllBtn = new Button(this);
        fetchAllBtn.setText("一键全取");
        Ui.styleButton(fetchAllBtn);
        fetchAllBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new Thread(new Runnable() {
                    @Override public void run() {
                        for (int i = 0; i < PAGES; i++) {
                            if (!fetched[i]) fetchPage(i, statusTv, numGrid);
                            try { Thread.sleep(120); } catch (InterruptedException ignored) {}
                        }
                    }
                }).start();
            }
        });
        root.addView(fetchAllBtn, Ui.wrap(10));

        // 答案输入
        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入答案（8位hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        root.addView(ansIn, Ui.fullWidth(10));

        // 提交
        Button subBtn = new Button(this);
        subBtn.setText("提交答案");
        Ui.styleButton(subBtn);
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (fetchedCount < PAGES) {
                    statusTv.setText("请先取完全部 " + PAGES + " 页数字");
                    return;
                }
                String input = ansIn.getText().toString().trim();
                String expected = RnBridge.nativeAnswer();
                if (input.equalsIgnoreCase(expected)) {
                    Celebration.show(tacticActivity.this, "FLAG_18_KL41{paper_strategy}");
                    PassLog.mark(tacticActivity.this, "KL41");
                    statusTv.setText("恭喜通关！");
                } else {
                    statusTv.setText("答案不对，请重试");
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        // 提示
        Button hintBtn = new Button(this);
        hintBtn.setText("提示");
        Ui.styleButton(hintBtn);
        hintBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(tacticActivity.this)
                    .setTitle("提示")
                    .setMessage("JS bundle 中的密钥被拆分成多个字符串片段，散布在 metro 混淆后的代码中。\n\n" +
                                "两个标记，一个通向真实签名，一个是纸上谈兵。\n" +
                                "仔细辨别拼写差异——真实密钥藏于 bundle 深处。\n\n" +
                                "签名算法为 HMAC-SHA256，用密钥对 \"page=N&ts=T\" 签名。")
                    .setPositiveButton("知道了", null)
                    .show();
            }
        });
        root.addView(hintBtn, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl41, 140));
        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }

    private OkHttpClient buildClient() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate ca = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(Tm.caDer()));
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("fatdog", ca);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tmf.getTrustManagers(), new SecureRandom());
            HostnameVerifier hv = new HostnameVerifier() {
                @Override public boolean verify(String h, SSLSession s) { return true; }
            };
            return new OkHttpClient.Builder()
                    .sslSocketFactory(sc.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0])
                    .hostnameVerifier(hv)
                    .connectTimeout(8, TimeUnit.SECONDS)
                    .readTimeout(8, TimeUnit.SECONDS)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void fetchPage(final int page, final TextView statusTv, final TextView numGrid) {
        if (page < 0 || page >= PAGES) return;
        final int pageNum = page + 1;
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    long ts = System.currentTimeMillis() / 1000;
                    String sign = RnBridge.nativeSign(pageNum, ts);
                    String url = NetHost.httpsBase() + "/api/kl41?page=" + pageNum + "&ts=" + ts + "&sign=" + sign;
                    OkHttpClient client = buildClient();
                    Request req = new Request.Builder().url(url).get().build();
                    Response resp = client.newCall(req).execute();
                    int code = resp.code();
                    if (code == 200) {
                        String json = resp.body().string();
                        String numsStr = json.substring(json.indexOf("[") + 1, json.lastIndexOf("]"));
                        String[] parts = numsStr.split(",");
                        for (int i = 0; i < parts.length && i < PER_PAGE; i++) {
                            allNums[page][i] = Integer.parseInt(parts[i].trim());
                        }
                        fetched[page] = true;
                        fetchedCount = countFetched();
                        totalSum = 0;
                        for (int p = 0; p < PAGES; p++)
                            if (fetched[p]) for (int v : allNums[p]) totalSum += v;
                        final int sum = totalSum;
                        final int cnt = fetchedCount;
                        runOnUiThread(new Runnable() {
                            @Override public void run() {
                                statusTv.setText("已取 " + cnt + "/" + PAGES + " 页 · 累计和: " + sum);
                                refreshPage(statusTv, numGrid);
                            }
                        });
                    } else {
                        runOnUiThread(new Runnable() {
                            @Override public void run() {
                                statusTv.setText("取数失败: HTTP " + code);
                            }
                        });
                    }
                } catch (Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            statusTv.setText("取数异常: " + e.getMessage());
                        }
                    });
                }
            }
        }).start();
    }

    private int countFetched() {
        int c = 0;
        for (boolean f : fetched) if (f) c++;
        return c;
    }

    private void refreshPage(TextView statusTv, TextView numGrid) {
        TextView pageTv = null;
        // 查找页码 TextView（nav 中间那个）
        statusTv.setText("已取 " + fetchedCount + "/" + PAGES + " 页 · 累计和: " + totalSum + " · 第 " + (currentPage + 1) + " 页");
        if (fetched[currentPage]) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < PER_PAGE; i++) {
                if (i > 0) sb.append("  ");
                sb.append(String.format("%3d", allNums[currentPage][i]));
            }
            numGrid.setText(sb.toString());
        } else {
            numGrid.setText("第 " + (currentPage + 1) + " 页未取 · 点击「取当前页」");
        }
    }
}
