package com.fatdog.reverse;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

// 太古禁地章节页：小说阅读器。
// 通关后点击 L1-L20 对应禁地，即按顺序阅读《太古执卷》卷一对应章节
// （正文来自 app/assets/novel/L1..L20.txt，首行=章名，其余=正文）。
// 其余关卡暂无正文，显示占位文案。
public class ForbiddenStoryActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String level = getIntent().getStringExtra("level");
        String title = getIntent().getStringExtra("title");
        if (level == null) level = "L?";
        if (title == null) title = "未知";

        // 读取章节正文（仅 L1..L20 有）
        String chapterTitle = null;
        String chapterBody = null;
        int n = chapterIndex(level);
        if (n > 0) {
            String raw = readAsset("novel/L" + n + ".txt");
            if (raw != null && raw.length() > 0) {
                int cut = raw.indexOf('\n');
                if (cut >= 0) {
                    chapterTitle = raw.substring(0, cut).trim();
                    chapterBody = raw.substring(cut + 1).trim();
                } else {
                    chapterTitle = raw.trim();
                    chapterBody = "";
                }
            }
        }

        FrameLayout root = new FrameLayout(this);
        ImageView bg = new ImageView(this);
        bg.setImageResource(R.drawable.bg_kunlun);
        bg.setScaleType(ImageView.ScaleType.CENTER_CROP);
        bg.setAlpha(0.12f);
        root.addView(bg, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));

        ScrollView scroll = new ScrollView(this);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(28), dp(28), dp(28), dp(32));
        scroll.addView(page);

        TextView titleTv = new TextView(this);
        titleTv.setText(chapterTitle != null ? chapterTitle : ("太古禁地 · " + title));
        titleTv.setTextSize(22);
        titleTv.setTypeface(Typeface.DEFAULT_BOLD);
        titleTv.setTextColor(0xFFFB7299);
        titleTv.setGravity(Gravity.CENTER);
        page.addView(titleTv, Ui.wrap(0));

        TextView subTv = new TextView(this);
        subTv.setText("太古禁地 · " + title);
        subTv.setTextSize(13);
        subTv.setTextColor(0xFF8A8A8A);
        subTv.setGravity(Gravity.CENTER);
        page.addView(subTv, Ui.wrap(6));

        TextView divider = new TextView(this);
        divider.setText("— — — —");
        divider.setTextSize(13);
        divider.setTextColor(0xFFC8C8D0);
        divider.setGravity(Gravity.CENTER);
        page.addView(divider, Ui.wrap(16));

        TextView body = new TextView(this);
        body.setTextSize(18);
        body.setTypeface(Typeface.SERIF);
        body.setLineSpacing(dp(8), 1.0f);
        body.setTextColor(0xFF3A3A42);
        if (chapterBody != null) {
            body.setText(indent(chapterBody));
        } else {
            body.setText("\u3000\u3000你立于太古禁地" + title + "的入口。石门之上，铭文流转，一道无形的力量封住了前路。"
                    + "据说这层禁地藏着一桩上古秘辛，唯有真正的逆术高手方能开启。"
                    + "\n\n\u3000\u3000你伸出手，指尖触到冰冷的石面，耳边仿佛响起古老的低语……"
                    + "\n\n\u3000\u3000本章内容敬请期待。");
        }
        page.addView(body, Ui.wrap(8));

        root.addView(scroll, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        setContentView(root);
        ThemeKit.apply(this);
    }

    // L1..L20 -> 1..20；其它关卡返回 0（无正文）
    private static int chapterIndex(String level) {
        if (level == null || level.length() < 2 || level.charAt(0) != 'L') return 0;
        String num = level.substring(1);
        for (int i = 0; i < num.length(); i++) {
            if (!Character.isDigit(num.charAt(i))) return 0;
        }
        try {
            int v = Integer.parseInt(num);
            return (v >= 1 && v <= 20) ? v : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    // 段前缩进两个全角空格；空行压缩为单换行（中文小说排版）
    private static String indent(String body) {
        StringBuilder sb = new StringBuilder();
        String[] lines = body.split("\n");
        for (String raw : lines) {
            String ln = raw.trim();
            if (ln.length() == 0) continue;
            if (sb.length() > 0) sb.append("\n");
            sb.append("\u3000\u3000").append(ln);
        }
        return sb.toString();
    }

    // 完整读取 assets 文本（UTF-8）；失败返回 null
    private String readAsset(String name) {
        try {
            InputStream is = getAssets().open(name);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
            is.close();
            return new String(bos.toByteArray(), "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
