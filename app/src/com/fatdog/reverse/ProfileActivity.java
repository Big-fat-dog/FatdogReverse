package com.fatdog.reverse;

import android.app.Activity;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.File;
import java.util.ArrayList;

// 个人主页：顶部"传送带"式分类条（基本情况 / 太古禁地 / 神念自察），可横向滑动；
// 下方内容随分类切换。基本情况 = 头像 + 境界 + 修仙进度；右上角昼夜切换；背景图。
public class ProfileActivity extends Activity {
    private static final int TOTAL_LEVELS = 25;   // 关卡 1-25（含 L20，L21-25 属第二季 SSL 系列）
    private static final String[] BIG_REALMS = {"炼气", "筑基", "金丹", "元婴", "化神"};
    private static final String[] LAYERS = {"一层", "二层", "三层", "四层", "五层"};
    private static final int[] REALM_COLORS = {
            0xFF67C23A, 0xFF409EFF, 0xFFE6A23C, 0xFFB37FEB, 0xFFFB7299
    };
    private static final String[] DESCS = {
            "引气入体，初窥门径",
            "筑基成功，道基已固",
            "金丹结成，脱胎换骨",
            "元婴出窍，遨游天地",
            "化神大能，一念千里"
    };
    private static final String[] AURAS = {
            "✦ 灵气初凝，吾道始启",
            "✦ 丹田之海，潮起潮落",
            "✦ 金丹璀璨，光耀四野",
            "✦ 元婴通神，窥见天机",
            "✦ 一念山河，一念星辰",
    };
    private static final String[] CAT_NAMES = {"基本情况", "太古禁地", "神念自察"};
    private static final int[] CAT_ICONS = {R.drawable.ic_tab_profile, R.drawable.ic_forbidden, R.drawable.ic_eye};
    private static final int[] CAT_COLORS = {0xFFFB7299, 0xFFFB7299, 0xFF409EFF};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildView(this, null, null));
    }

    static View buildView(final Context ctx, final View.OnClickListener avatarClick,
                          final Runnable onToggleDone) {
        boolean dark = ThemeKit.isDark(ctx);

        FrameLayout root = new FrameLayout(ctx);
        root.setLayoutParams(new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));

        // 背景图
        ImageView bg = new ImageView(ctx);
        bg.setImageResource(R.drawable.bg_profile);
        bg.setScaleType(ImageView.ScaleType.CENTER_CROP);
        bg.setAlpha(0.20f);
        root.addView(bg, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));

        LinearLayout column = new LinearLayout(ctx);
        column.setOrientation(LinearLayout.VERTICAL);
        root.addView(column, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));

        // 传送带分类条：小图标 + 名称，可横向滑动
        HorizontalScrollView hsv = new HorizontalScrollView(ctx);
        hsv.setHorizontalScrollBarEnabled(false);
        LinearLayout catBar = new LinearLayout(ctx);
        catBar.setOrientation(LinearLayout.HORIZONTAL);
        catBar.setPadding(dp(ctx, 14), dp(ctx, 12), dp(ctx, 14), dp(ctx, 8));
        hsv.addView(catBar);
        column.addView(hsv, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        // 内容宿主
        FrameLayout contentHost = new FrameLayout(ctx);
        contentHost.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT));
        column.addView(contentHost);

        final View[] pages = new View[3];
        pages[0] = buildBasicInfo(ctx, avatarClick);
        pages[1] = ForbiddenLandActivity.buildLandView((Activity) ctx);
        pages[2] = DivineReflectionActivity.buildReflectionView((Activity) ctx);
        for (View p : pages) {
            contentHost.addView(p, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.MATCH_PARENT));
        }

        final ArrayList<TextView> chips = new ArrayList<TextView>();
        for (int i = 0; i < CAT_NAMES.length; i++) {
            final int idx = i;
            TextView chip = new TextView(ctx);
            chip.setText(CAT_NAMES[i]);
            chip.setTextSize(13);
            chip.setTypeface(Typeface.DEFAULT_BOLD);
            chip.setGravity(Gravity.CENTER);
            chip.setPadding(dp(ctx, 14), dp(ctx, 7), dp(ctx, 14), dp(ctx, 7));
            LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            clp.rightMargin = dp(ctx, 8);
            catBar.addView(chip, clp);
            chip.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    selectPage(ctx, idx, chips, pages);
                }
            });
            chips.add(chip);
        }

        selectPage(ctx, 0, chips, pages);

        // 右上角昼夜切换
        if (onToggleDone != null) {
            final ImageButton tb = new ImageButton(ctx);
            tb.setImageResource(dark ? R.drawable.ic_sun : R.drawable.ic_moon);
            tb.setColorFilter(dark ? 0xFFECECF2 : 0xFF1B1B1F);
            tb.setBackgroundResource(R.drawable.bg_theme_btn);
            tb.setScaleType(ImageView.ScaleType.CENTER);
            FrameLayout.LayoutParams tbLp = new FrameLayout.LayoutParams(dp(ctx, 44), dp(ctx, 44));
            tbLp.gravity = Gravity.TOP | Gravity.RIGHT;
            tbLp.topMargin = dp(ctx, 8);
            tbLp.rightMargin = dp(ctx, 12);
            tb.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    ThemeKit.animateToggle((Activity) ctx, new Runnable() {
                        @Override
                        public void run() {
                            if (onToggleDone != null) onToggleDone.run();
                        }
                    });
                }
            });
            root.addView(tb, tbLp);
        }

        return root;
    }

    // 切换分类：更新胶囊样式 + 内容可见性
    private static void selectPage(Context ctx, int idx, ArrayList<TextView> chips, View[] pages) {
        boolean dark = ThemeKit.isDark(ctx);
        for (int i = 0; i < chips.size(); i++) {
            boolean sel = (i == idx);
            GradientDrawable g = new GradientDrawable();
            g.setShape(GradientDrawable.RECTANGLE);
            g.setCornerRadius(dp(ctx, 16));
            g.setColor(sel ? CAT_COLORS[i] : (dark ? 0xFF24242B : 0xFFF1F1F4));
            chips.get(i).setBackground(g);
            chips.get(i).setTextColor(sel ? Color.WHITE : (dark ? 0xFFD8D8E0 : 0xFF3A3A42));
            Drawable ic = ctx.getResources().getDrawable(CAT_ICONS[i]).mutate();
            int tint = sel ? Color.WHITE : (dark ? 0xFFD8D8E0 : 0xFF3A3A42);
            ic.setColorFilter(tint, PorterDuff.Mode.SRC_IN);
            ic.setBounds(0, 0, dp(ctx, 18), dp(ctx, 18));
            chips.get(i).setCompoundDrawables(ic, null, null, null);
        }
        for (int i = 0; i < pages.length; i++) {
            pages[i].setVisibility(i == idx ? View.VISIBLE : View.GONE);
        }
    }

    // 基本情况：头像 + 境界 + 修仙进度
    private static View buildBasicInfo(Context ctx, final View.OnClickListener avatarClick) {
        boolean dark = ThemeKit.isDark(ctx);
        int n = PassLog.count(ctx);
        int realmColor = realmColor(n);
        int textColor = ThemeKit.text(dark);
        int mutedColor = ThemeKit.muted(dark);

        LinearLayout box = new LinearLayout(ctx);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER);
        box.setPadding(dp(ctx, 36), dp(ctx, 24), dp(ctx, 36), dp(ctx, 24));
        box.setLayoutParams(new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));

        // 头像
        final CircleAvatarView avatar = new CircleAvatarView(ctx);
        avatar.setClickable(avatarClick != null);
        if (avatarClick != null) avatar.setOnClickListener(avatarClick);
        avatar.setBitmap(loadAvatarBitmap(ctx));
        box.addView(avatar, new LinearLayout.LayoutParams(dp(ctx, 104), dp(ctx, 104)));

        TextView avHint = new TextView(ctx);
        avHint.setText("点击头像可更换");
        avHint.setTextSize(12);
        avHint.setTextColor(mutedColor);
        box.addView(avHint, Ui.wrap(6));

        // 境界徽章
        TextView realm = new TextView(ctx);
        realm.setText(realmName(n));
        realm.setTextSize(26);
        realm.setTypeface(Typeface.DEFAULT_BOLD);
        realm.setTextColor(Color.WHITE);
        realm.setGravity(Gravity.CENTER);
        GradientDrawable badge = new GradientDrawable();
        badge.setShape(GradientDrawable.RECTANGLE);
        badge.setColor(realmColor);
        badge.setCornerRadius(dp(ctx, 30f));
        badge.setStroke(dp(ctx, 2f), 0x44FFFFFF);
        realm.setBackground(badge);
        realm.setPadding(dp(ctx, 32), dp(ctx, 10), dp(ctx, 32), dp(ctx, 10));
        LinearLayout.LayoutParams realmLp = Ui.wrap(16);
        realmLp.bottomMargin = dp(ctx, 12);
        box.addView(realm, realmLp);

        TextView aura = new TextView(ctx);
        aura.setText(AURAS[auraIdx(n)]);
        aura.setTextSize(14);
        aura.setTextColor(mutedColor);
        box.addView(aura, Ui.wrap(2));

        TextView desc = new TextView(ctx);
        desc.setText(realmDesc(n));
        desc.setTextSize(16);
        desc.setTextColor(textColor);
        box.addView(desc, Ui.wrap(2));

        // 修仙进度条（固定高度）
        box.addView(progressBar(ctx, n, realmColor));

        TextView progress = new TextView(ctx);
        progress.setText("已通关 " + n + " / " + TOTAL_LEVELS + " 关");
        progress.setTextSize(14);
        progress.setTextColor(mutedColor);
        box.addView(progress, Ui.wrap(10));

        TextView next = new TextView(ctx);
        next.setText(nextRealmHint(n));
        next.setTextSize(14);
        next.setTextColor(textColor);
        box.addView(next, Ui.wrap(6));

        return box;
    }

    private static View progressBar(Context ctx, int n, int realmColor) {
        boolean dark = ThemeKit.isDark(ctx);
        int filled = Math.round(n * 10.0f / TOTAL_LEVELS);

        LinearLayout bar = new LinearLayout(ctx);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams barLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(ctx, 14));
        barLp.topMargin = dp(ctx, 18);
        barLp.leftMargin = dp(ctx, 18);
        barLp.rightMargin = dp(ctx, 18);
        bar.setLayoutParams(barLp);

        GradientDrawable track = new GradientDrawable();
        track.setShape(GradientDrawable.RECTANGLE);
        track.setCornerRadius(dp(ctx, 7f));
        track.setColor(dark ? 0xFF3A3A42 : 0xFFE9E9EE);

        GradientDrawable fill = new GradientDrawable();
        fill.setShape(GradientDrawable.RECTANGLE);
        fill.setCornerRadius(dp(ctx, 7f));
        fill.setColor(realmColor);

        View fillV = new View(ctx);
        fillV.setBackground(fill);
        View emptyV = new View(ctx);
        emptyV.setBackground(track);
        bar.addView(fillV, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.MATCH_PARENT, filled));
        bar.addView(emptyV, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.MATCH_PARENT, 10 - filled));
        return bar;
    }

    private static int dp(Context c, float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                c.getResources().getDisplayMetrics());
    }

    private static int auraIdx(int n) {
        if (n <= 0) return 0;
        return Math.min((n - 1) / 5, AURAS.length - 1);
    }

    static String realmName(int n) {
        if (n <= 0) return "凡人";
        int idx = Math.min((n - 1) / 5, BIG_REALMS.length - 1);
        int layer = (n - 1) % 5;
        return BIG_REALMS[idx] + " " + LAYERS[layer];
    }

    static int realmColor(int n) {
        if (n <= 0) return 0xFF9E9E9E;
        return REALM_COLORS[Math.min((n - 1) / 5, REALM_COLORS.length - 1)];
    }

    static String realmDesc(int n) {
        if (n <= 0) return "尚未踏上修炼之路";
        return DESCS[Math.min((n - 1) / 5, DESCS.length - 1)];
    }

    static String nextRealmHint(int n) {
        if (n <= 0) return "再通 1 关，踏入炼气";
        int idx = (n - 1) / 5;
        if (idx + 1 < BIG_REALMS.length) {
            int need = (idx + 1) * 5 + 1 - n;
            return "再通 " + need + " 关，迈入" + BIG_REALMS[idx + 1];
        }
        return "已达" + BIG_REALMS[idx] + "，可冲击更高境界";
    }

    static Bitmap loadAvatarBitmap(Context ctx) {
        Bitmap bm = null;
        File f = new File(ctx.getFilesDir(), "avatar.jpg");
        if (f.exists()) {
            BitmapFactory.Options o = new BitmapFactory.Options();
            o.inJustDecodeBounds = true;
            BitmapFactory.decodeFile(f.getAbsolutePath(), o);
            int sample = 1;
            int side = Math.max(o.outWidth, o.outHeight);
            while (side / (sample * 2) >= 256) sample *= 2;
            o = new BitmapFactory.Options();
            o.inSampleSize = sample;
            bm = BitmapFactory.decodeFile(f.getAbsolutePath(), o);
        }
        if (bm == null) {
            bm = BitmapFactory.decodeResource(ctx.getResources(), R.drawable.avatar_default);
        }
        Bitmap scaled = Bitmap.createScaledBitmap(bm, 256, 256, true);
        if (scaled != bm) bm.recycle();
        return scaled;
    }
}