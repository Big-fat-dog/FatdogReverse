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

// 太古禁地章节页：小说阅读器样式，内容目前统一"敬请期待"。
public class ForbiddenStoryActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String level = getIntent().getStringExtra("level");
        String title = getIntent().getStringExtra("title");
        if (level == null) level = "L?";
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
        titleTv.setText("太古禁地 · " + title);
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
        body.setText("\u3000\u3000你立于太古禁地" + title + "的入口。石门之上，铭文流转，一道无形的力量封住了前路。"
                + "据说这层禁地藏着一桩上古秘辛，唯有真正的逆术高手方能开启。"
                + "\n\n\u3000\u3000你伸出手，指尖触到冰冷的石面，耳边仿佛响起古老的低语……"
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