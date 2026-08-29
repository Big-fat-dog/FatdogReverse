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

/**
 * 天地秘境章节页：小说阅读器样式。
 * 每关一个故事，从 ProfileActivity 天地秘境点击进入。
 * 接收 extras: level（关卡 ID）、title（关卡名）。
 */
public class DivineStoryActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String level = getIntent().getStringExtra("level");
        String title = getIntent().getStringExtra("title");
        if (level == null) level = "KL?";
        if (title == null) title = "未知";

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
        titleTv.setText("天地秘境 · " + title);
        titleTv.setTextSize(22);
        titleTv.setTypeface(Typeface.DEFAULT_BOLD);
        titleTv.setTextColor(0xFFFB7299);
        titleTv.setGravity(Gravity.CENTER);
        page.addView(titleTv, Ui.wrap(0));

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
        body.setText("\u3000\u3000你踏入天地秘境之" + title + "。四周灵气翻涌，天地法则在此交织，化作一道道看不见的锁链。"
                + "据说这片秘境藏着上古大能留下的传承，唯有洞悉天地玄机者方能参悟。"
                + "\n\n\u3000\u3000你深吸一口气，灵台清明，逆向心法运转，眼前的世界开始变得透明……"
                + "\n\n\u3000\u3000本章内容敬请期待。");
        page.addView(body, Ui.wrap(8));

        root.addView(scroll, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        setContentView(root);
        ThemeKit.apply(this);
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
