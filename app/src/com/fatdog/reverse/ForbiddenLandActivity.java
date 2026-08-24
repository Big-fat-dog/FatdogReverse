package com.fatdog.reverse;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

// 太古禁地：每一关对应一层禁地，通关解锁，未通过的显示为灰色锁状。
// buildLandView() 可作为内容嵌入个人主页的"太古禁地"分类。
public class ForbiddenLandActivity extends Activity {
    private static final String[] LEVEL_IDS = {
            "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8",
            "L9", "L10", "L11", "L12", "L13", "L14", "L15", "L16",
            "L17", "L18", "L19", "L20", "L21", "L22", "L23", "L24", "L25", "L26", "L27", "L28", "L29", "L30", "L31", "L32", "L33", "L34", "L35", "L36", "L37", "L38", "L39", "L40", "L41", "L42", "L43", "L44"};
    private static final String[] LEVEL_NAMES = {
            "第 1 层", "第 2 层", "第 3 层", "第 4 层", "第 5 层", "第 6 层", "第 7 层", "第 8 层",
            "第 9 层", "第 10 层", "第 11 层", "第 12 层", "第 13 层", "第 14 层", "第 15 层", "第 16 层",
            "第 17 层", "第 18 层", "第 19 层", "第 20 层 · 万恶广告劫", "第 21 层", "第 22 层", "第 23 层",
            "第 24 层", "第 25 层", "第 26 层 · 双符合璧", "第 27 层 · 万法归宗", "第 28 层 · 缄默之钥", "第 29 层 · 隐姓埋名", "第 30 层 · 无名剑冢", "第 31 层 · 两界穿针", "第 32 层 · 心魔哨兵", "第 33 层 · 金刚不坏", "第 34 层 · 万法归墟", "第 35 层 · 双匣暗渡", "第 36 层 · 查表识君", "第 37 层 · 雪崩之谜", "第 38 层 · 初探模块", "第 39 层 · 偷梁换柱", "第 40 层 · 探囊取物", "第 41 层 · 斩关夺隘", "第 42 层 · 万剑归宗", "第 43 层 · 照妖之镜", "第 44 层 · 偷天换日"};

    private static final int PER_ROW = 4;            // 每行格子数
    private static final int ROWS_FIRST = 2;         // 种子行数下限
    private static final int ROWS_BATCH = 2;         // 下滑每次追加行数
    private static final int ROW_HEIGHT_EST_DP = 88; // 行高保守估算值

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        FrameLayout root = new FrameLayout(this);
        ImageView bg = new ImageView(this);
        bg.setImageResource(R.drawable.bg_kunlun);
        bg.setScaleType(ImageView.ScaleType.CENTER_CROP);
        bg.setAlpha(0.16f);
        root.addView(bg, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        root.addView(buildPage(this), new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        setContentView(root);
        ThemeKit.apply(this);
    }

    // 独立页面：返回头 + 禁地格子
    private static View buildPage(final Activity act) {
        LinearLayout col = new LinearLayout(act);
        col.setOrientation(LinearLayout.VERTICAL);

        LinearLayout header = new LinearLayout(act);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(act, 8), dp(act, 16), dp(act, 16), dp(act, 8));
        TextView back = new TextView(act);
        back.setText("‹ 返回");
        back.setTextSize(16);
        back.setTextColor(0xFFFB7299);
        back.setPadding(dp(act, 12), dp(act, 4), dp(act, 12), dp(act, 4));
        back.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                act.finish();
            }
        });
        header.addView(back, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));
        TextView title = new TextView(act);
        title.setText("太古禁地");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(0xFFFB7299);
        title.setGravity(Gravity.CENTER);
        header.addView(title, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        col.addView(header);

        TextView tip = new TextView(act);
        tip.setText("每闯过一关，对应的禁地便会开启");
        tip.setTextSize(13);
        tip.setTextColor(0xFF8A8A8A);
        tip.setGravity(Gravity.CENTER);
        col.addView(tip, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        col.addView(buildLandView(act), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT));
        return col;
    }

    // 可嵌入内容：禁地格子（4 列），无页头。
    // 首屏按屏幕高度直接铺满（不依赖布局回调），下滑到底部附近再继续补格子
    static View buildLandView(final Activity act) {
        final ScrollView scroll = new ScrollView(act);
        final LinearLayout list = new LinearLayout(act);
        list.setOrientation(LinearLayout.VERTICAL);
        list.setPadding(dp(act, 14), dp(act, 8), dp(act, 14), dp(act, 20));
        scroll.addView(list);

        final int totalRows = (LEVEL_IDS.length + PER_ROW - 1) / PER_ROW;
        // 行高按保守小值估算（真实约 100dp+），宁多勿少：保证种子行数一定溢出一屏
        int screenH = act.getResources().getDisplayMetrics().heightPixels;
        int fillRows = Math.max(ROWS_FIRST, screenH / dp(act, ROW_HEIGHT_EST_DP) + 2);

        final int[] rows = {0};
        appendRows(act, list, rows, Math.min(fillRows, totalRows));

        // 布局变化（含首次）后自查：万一估算偏少没铺满，继续补到满为止
        list.addOnLayoutChangeListener(new View.OnLayoutChangeListener() {
            @Override
            public void onLayoutChange(View v, int l, int t, int r, int b,
                                       int ol, int ot, int or2, int ob) {
                maybeLoadMore(act, list, rows, totalRows, scroll);
            }
        });
        // 下滑时：接近底部（140dp 内）继续追加
        scroll.getViewTreeObserver().addOnScrollChangedListener(new ViewTreeObserver.OnScrollChangedListener() {
            @Override
            public void onScrollChanged() {
                maybeLoadMore(act, list, rows, totalRows, scroll);
            }
        });
        return scroll;
    }

    private static void appendRows(Activity act, LinearLayout list, int[] rows, int until) {
        for (int r = rows[0]; r < until; r++) {
            LinearLayout row = new LinearLayout(act);
            row.setOrientation(LinearLayout.HORIZONTAL);
            for (int j = r * PER_ROW; j < Math.min((r + 1) * PER_ROW, LEVEL_IDS.length); j++) {
                // 固定格高：名称长短不再影响方块大小（长名单行省略，点开看全称）
                row.addView(buildCell(act, j), new LinearLayout.LayoutParams(0,
                        dp(act, 96), 1f));
            }
            list.addView(row, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT));
        }
        if (until > rows[0]) rows[0] = until;
    }

    // 内容不足一屏、或滚动位置距底部 140dp 内时，再补 ROWS_BATCH 行
    private static void maybeLoadMore(final Activity act, final LinearLayout list,
                                      final int[] rows, final int totalRows, final ScrollView scroll) {
        if (rows[0] >= totalRows || list.getHeight() == 0) return;
        boolean shortPage = list.getHeight() <= scroll.getHeight();
        boolean nearBottom = scroll.getScrollY() + scroll.getHeight()
                >= list.getHeight() - dp(act, 140);
        if (!shortPage && !nearBottom) return;
        appendRows(act, list, rows, Math.min(rows[0] + ROWS_BATCH, totalRows));
    }

    private static View buildCell(final Activity act, final int idx) {
        final boolean done = PassLog.isDone(act, LEVEL_IDS[idx]);
        LinearLayout cell = new LinearLayout(act);
        cell.setOrientation(LinearLayout.VERTICAL);
        cell.setGravity(Gravity.CENTER);
        cell.setPadding(dp(act, 8), dp(act, 14), dp(act, 8), dp(act, 14));

        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.RECTANGLE);
        g.setCornerRadius(dp(act, 12));
        g.setColor(done ? 0xFFFB7299 : 0xCC24242B);
        cell.setBackground(g);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(dp(act, 4), dp(act, 4), dp(act, 4), dp(act, 4));
        cell.setLayoutParams(lp);

        if (done) {
            ImageView star = new ImageView(act);
            star.setImageResource(R.drawable.ic_star);
            star.setColorFilter(0xFFFFFFFF);
            cell.addView(star, new LinearLayout.LayoutParams(dp(act, 18), dp(act, 18)));
            TextView big = new TextView(act);
            big.setText(LEVEL_IDS[idx]);
            big.setTextSize(17);
            big.setTypeface(Typeface.DEFAULT_BOLD);
            big.setTextColor(0xFFFFFFFF);
            cell.addView(big, Ui.wrap(4));
            TextView small = new TextView(act);
            small.setText(LEVEL_NAMES[idx]);
            small.setTextSize(11);
            small.setTextColor(0xCCFFFFFF);
            small.setSingleLine(true);
            small.setEllipsize(android.text.TextUtils.TruncateAt.END);
            cell.addView(small, Ui.wrap(1));
            cell.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    Intent intent = new Intent(act, ForbiddenStoryActivity.class);
                    intent.putExtra("level", LEVEL_IDS[idx]);
                    intent.putExtra("title", LEVEL_NAMES[idx]);
                    act.startActivity(intent);
                }
            });
        } else {
            ImageView lock = new ImageView(act);
            lock.setImageResource(R.drawable.ic_lock);
            lock.setColorFilter(0xFF9A9AA3);
            cell.addView(lock, new LinearLayout.LayoutParams(dp(act, 18), dp(act, 18)));
            TextView big = new TextView(act);
            big.setText(LEVEL_IDS[idx]);
            big.setTextSize(17);
            big.setTypeface(Typeface.DEFAULT_BOLD);
            big.setTextColor(0xFF9A9AA3);
            cell.addView(big, Ui.wrap(4));
            TextView small = new TextView(act);
            small.setText(LEVEL_NAMES[idx]);
            small.setTextSize(11);
            small.setTextColor(0xFF77777F);
            small.setSingleLine(true);
            small.setEllipsize(android.text.TextUtils.TruncateAt.END);
            cell.addView(small, Ui.wrap(1));
        }
        return cell;
    }

    private static int dp(Activity a, float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                a.getResources().getDisplayMetrics());
    }
}
