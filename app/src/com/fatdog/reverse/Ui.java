package com.fatdog.reverse;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;

// 关卡页面通用构件：底部完整显示图片、统一的控件间距。
public class Ui {
    // 与关卡选择按钮同款样式：黑底渐变 + 粉色描边 + 圆角 + 水波纹
    public static void styleButton(Button b) {
        b.setBackgroundResource(R.drawable.bg_level_btn);
        b.setTextColor(0xFFECECF2);
        b.setTextSize(15);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setMinHeight(dp(46));
        b.setPadding(dp(20), dp(8), dp(20), dp(8));
    }

    // 底部横幅：占满剩余高度、完整显示整张图（FIT_CENTER 不裁剪）
    public static ImageView banner(Context c, int res) {
        ImageView iv = new ImageView(c);
        iv.setImageResource(res);
        iv.setScaleType(ImageView.ScaleType.FIT_CENTER);
        iv.setAlpha(0.92f);
        iv.setPadding(0, dp(10), 0, 0);
        iv.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        return iv;
    }

    // 固定高度的底部横幅（网络关 ListView 占满剩余高度时用）
    public static ImageView banner(Context c, int res, int fixedDp) {
        ImageView iv = new ImageView(c);
        iv.setImageResource(res);
        iv.setScaleType(ImageView.ScaleType.FIT_CENTER);
        iv.setAlpha(0.92f);
        iv.setPadding(0, dp(8), 0, 0);
        iv.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(fixedDp)));
        return iv;
    }

    public static LinearLayout.LayoutParams fullWidth() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    public static LinearLayout.LayoutParams fullWidth(int topDp) {
        LinearLayout.LayoutParams p = fullWidth();
        p.topMargin = dp(topDp);
        return p;
    }

    public static LinearLayout.LayoutParams wrap() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    public static LinearLayout.LayoutParams wrap(int topDp) {
        LinearLayout.LayoutParams p = wrap();
        p.topMargin = dp(topDp);
        return p;
    }

    // 将 LinearLayout 包裹进 ScrollView，使内容可滚动
    public static ScrollView wrapScroll(LinearLayout content) {
        ScrollView sv = new ScrollView(content.getContext());
        sv.setFillViewport(true);
        sv.addView(content);
        return sv;
    }

    public static int dp(int v) {
        return Math.round(v * Resources.getSystem().getDisplayMetrics().density);
    }
}