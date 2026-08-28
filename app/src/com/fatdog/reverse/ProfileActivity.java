package com.fatdog.reverse;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.AlertDialog;
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
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.EditText;
import android.widget.TextView;

import java.io.File;
import java.util.ArrayList;

// 个人主页：顶部"传送带"式分类条（基本情况 / 太古禁地 / 神念自察），可横向滑动；
// 下方内容随分类切换。基本情况 = 头像 + 境界 + 修仙进度；右上角昼夜切换；背景图。
public class ProfileActivity extends Activity {
    private static final int TOTAL_LEVELS = 53;   // 关卡 1-46（含 L20，L21-27 属 SSL/抓包系列，L28-37 起 native 第三季，KL1-10 天地秘境，L38-42 Xposed 第四季，L43-46 签名校验对抗）
    // 炼气~元婴：每 5 关一层（1-20）；化神起：每 10 关一个大境界，第 10 层为"圆满"；
    // 高阶四境之后是终点"独断万古"——通关数再多也停在它上面。
    private static final String[] BIG_REALMS = {"炼气", "筑基", "金丹", "元婴"};
    private static final String[] HIGH_REALMS = {"化神", "洞虚", "归墟", "无量"};
    private static final String FINAL_REALM = "独断万古";
    private static final String[] LAYERS = {
            "一层", "二层", "三层", "四层", "五层", "六层", "七层", "八层", "九层"
    };
    // 下一个大境界的门槛（通关数）与名称，nextRealmHint 用
    private static final int[] NEXT_AT = {6, 11, 16, 21, 31, 41, 51, 61};
    private static final String[] NEXT_NAME = {"筑基", "金丹", "元婴", "化神", "洞虚", "归墟", "无量", FINAL_REALM};
    private static final int[] REALM_COLORS = {
            0xFF67C23A, 0xFF409EFF, 0xFFE6A23C, 0xFFB37FEB,
            0xFFFB7299, 0xFF36CFC9, 0xFF2F54EB, 0xFFFADB14, 0xFFB8965A
    };
    // 终点境界专属：深空紫黑渐变 + 鎏金描边/光晕
    private static final int[] FINAL_BADGE_COLORS = {0xFF1F1C2C, 0xFF4A3B6B};
    private static final int FINAL_GLOW_COLOR = 0xFFF7C873;
    private static final int FINAL_EDGE_COLOR = 0x66F7C873;
    private static final String[] DESCS = {
            "引气入体，初窥门径",
            "筑基成功，道基已固",
            "金丹结成，脱胎换骨",
            "元婴出窍，遨游天地",
            "化神大能，一念千里",
            "洞虚观世，勘破虚妄",
            "万法归墟，百川朝宗",
            "无量无边，不可思议",
            "独断万古，古今唯一"
    };
    private static final String[] AURAS = {
            "✦ 灵气初凝，吾道始启",
            "✦ 丹田之海，潮起潮落",
            "✦ 金丹璀璨，光耀四野",
            "✦ 元婴通神，窥见天机",
            "✦ 一念山河，一念星辰",
            "✦ 虚妄皆破，唯道独行",
            "✦ 沧海归墟，万象臣服",
            "✦ 一念无量，光寿无涯",
            "✦ 万古长夜，我为天明",
    };
    private static final String[] CAT_NAMES = {"基本情况", "太古禁地", "神念自察", "天地秘境"};
    private static final int[] CAT_ICONS = {R.drawable.ic_tab_profile, R.drawable.ic_forbidden, R.drawable.ic_eye, R.drawable.ic_lock};
    private static final int[] CAT_COLORS = {0xFFFB7299, 0xFFFB7299, 0xFF409EFF, 0xFF00BFA5};

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

        final View[] pages = new View[4];
        pages[0] = buildBasicInfo(ctx, avatarClick);
        pages[1] = ForbiddenLandActivity.buildLandView((Activity) ctx);
        pages[2] = DivineReflectionActivity.buildReflectionView((Activity) ctx);
        pages[3] = buildKunlunPlaceholder(ctx);
        for (View p : pages) {
            contentHost.addView(p, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.MATCH_PARENT));
        }

        final ArrayList<TextView> chips = new ArrayList<TextView>();
        // 昼夜切换按钮只在"基本情况"页显示；先占位，创建后再回填引用
        final ImageButton[] themeBtn = new ImageButton[1];
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
                    // 太古禁地 / 天地秘境默认开放，无需通关数门禁
                    selectPage(ctx, idx, chips, pages);
                    if (themeBtn[0] != null) {
                        themeBtn[0].setVisibility(idx == 0 ? View.VISIBLE : View.GONE);
                    }
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
            tbLp.topMargin = dp(ctx, 52);
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
            themeBtn[0] = tb;   // 回填引用，供分类切换时控制显隐
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

        // 境界徽章（化神起带柔和呼吸光晕；终点境界为深空鎏金渐变）
        TextView realm = new TextView(ctx);
        realm.setText(realmName(n));
        realm.setTextSize(26);
        realm.setTypeface(Typeface.DEFAULT_BOLD);
        realm.setTextColor(Color.WHITE);
        realm.setGravity(Gravity.CENTER);
        boolean finale = isFinalRealm(n);
        GradientDrawable badge = new GradientDrawable();
        badge.setShape(GradientDrawable.RECTANGLE);
        badge.setCornerRadius(dp(ctx, 30f));
        if (finale) {
            badge.setColors(FINAL_BADGE_COLORS);
            badge.setOrientation(GradientDrawable.Orientation.TL_BR);
            badge.setStroke(dp(ctx, 2f), FINAL_EDGE_COLOR);
        } else {
            badge.setColor(realmColor(n));
            badge.setStroke(dp(ctx, 2f), 0x44FFFFFF);
        }
        realm.setBackground(badge);
        realm.setPadding(dp(ctx, 32), dp(ctx, 10), dp(ctx, 32), dp(ctx, 10));
        LinearLayout.LayoutParams realmLp = Ui.wrap(16);
        realmLp.bottomMargin = dp(ctx, 12);
        if (hasDivineGlow(n)) {
            View glow = new View(ctx);
            GradientDrawable gd = new GradientDrawable();
            gd.setShape(GradientDrawable.RECTANGLE);
            gd.setCornerRadius(dp(ctx, 36f));
            gd.setColor(finale ? FINAL_GLOW_COLOR : realmColor(n));
            glow.setBackground(gd);
            FrameLayout badgeHost = new FrameLayout(ctx);
            FrameLayout.LayoutParams glp = new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.MATCH_PARENT);
            int m = dp(ctx, 7);
            glp.setMargins(-m, -m, -m, -m);   // 光晕向四周溢出 7dp
            badgeHost.addView(glow, glp);
            badgeHost.addView(realm, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT));
            box.addView(badgeHost, realmLp);
            startDivinePulse(glow, realm);
        } else {
            box.addView(realm, realmLp);
        }

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


    /* 天地秘境占位：后续填入通关后的小说阅读器 */
    private static View buildKunlunPlaceholder(Context ctx) {
        ScrollView scroll = new ScrollView(ctx);
        LinearLayout col = new LinearLayout(ctx);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(ctx,20), dp(ctx,16), dp(ctx,20), dp(ctx,24));
        TextView tip = new TextView(ctx);
        tip.setText("此方天地尚未完全开辟……\n通关昆仑山关卡后，此处将浮现属于你的故事。");
        tip.setTextSize(13); tip.setTextColor(ThemeKit.muted(ThemeKit.isDark(ctx)));
        tip.setGravity(Gravity.CENTER); tip.setPadding(0, dp(ctx,30), 0, dp(ctx,20));
        col.addView(tip);
        TextView zone=new TextView(ctx);
        zone.setText("—— 昆仑山 ——");
        zone.setTextSize(12); zone.setTextColor(0xFFFB7299);
        zone.setGravity(Gravity.CENTER);
        zone.setPadding(0,dp(ctx,10),0,dp(ctx,4));
        col.addView(zone);
        String[] kn={"山门","引雷桩","渡鸦桥","冰裂缝","登顶"};
        for(int i=1;i<=5;i++){
            boolean open=PassLog.isDone(ctx,"KL"+i);
            LinearLayout row=new LinearLayout(ctx); row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL); row.setPadding(dp(ctx,10),dp(ctx,12),dp(ctx,10),dp(ctx,12));
            GradientDrawable g=new GradientDrawable(); g.setCornerRadius(dp(ctx,10));
            g.setColor(open?0x33FB7299:(ThemeKit.isDark(ctx)?0xCC24242B:0x22EEEEEE)); row.setBackground(g);
            TextView t=new TextView(ctx); t.setText((open?"✦ ":"🔒 ")+"KL"+i+" · "+kn[i-1]);
            t.setTextSize(15); t.setTypeface(Typeface.DEFAULT_BOLD);
            t.setTextColor(open?0xFFFB7299:(ThemeKit.isDark(ctx)?0xFF77777F:0xFFAAAAAA));
            row.addView(t,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));
            LinearLayout.LayoutParams mlp=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT);
            mlp.topMargin=dp(ctx,6); col.addView(row,mlp);
        }
        TextView zone2=new TextView(ctx);
        zone2.setText("—— 流沙河 ——");
        zone2.setTextSize(12); zone2.setTextColor(0xFFFB7299);
        zone2.setGravity(Gravity.CENTER);
        zone2.setPadding(0,dp(ctx,10),0,dp(ctx,4));
        col.addView(zone2);
        String[] lsh={"冰封之钥","裂魂之匣","幽泉之眼","天罡北斗","万象归一"};
        for(int i=0;i<lsh.length;i++){
            boolean open=PassLog.isDone(ctx,"KL"+(i+6));
            LinearLayout row=new LinearLayout(ctx); row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL); row.setPadding(dp(ctx,10),dp(ctx,12),dp(ctx,10),dp(ctx,12));
            GradientDrawable g=new GradientDrawable(); g.setCornerRadius(dp(ctx,10));
            g.setColor(open?0x33FB7299:(ThemeKit.isDark(ctx)?0xCC24242B:0x22EEEEEE)); row.setBackground(g);
            TextView t=new TextView(ctx); t.setText((open?"✦ ":"🔒 ")+"KL"+(i+6)+" · "+lsh[i]);
            t.setTextSize(15); t.setTypeface(Typeface.DEFAULT_BOLD);
            t.setTextColor(open?0xFFFB7299:(ThemeKit.isDark(ctx)?0xFF77777F:0xFFAAAAAA));
            row.addView(t,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));
            LinearLayout.LayoutParams mlp=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT);
            mlp.topMargin=dp(ctx,6); col.addView(row,mlp);
        }
        scroll.addView(col); return scroll;
    }

    private static int dp(Context c, float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                c.getResources().getDisplayMetrics());
    }

    // 化神（21 关）起有神辉特效；终点境界独占鎏金光晕
    private static boolean hasDivineGlow(int n) {
        return n >= 21;
    }

    private static boolean isFinalRealm(int n) {
        return n >= NEXT_AT[NEXT_AT.length - 1];
    }

    // 数组下标换算：0=炼气 … 3=元婴，4=化神 … 7=无量，8+=终点（钳制到最后一位）
    private static int realmIdx(int n) {
        if (n <= 0) return 0;
        if (n <= 20) return (n - 1) / 5;
        return Math.min((n - 21) / 10 + BIG_REALMS.length, REALM_COLORS.length - 1);
    }

    static String realmName(int n) {
        if (n <= 0) return "凡人";
        if (n <= 20) {
            return BIG_REALMS[(n - 1) / 5] + " " + LAYERS[(n - 1) % 5];
        }
        int hi = (n - 21) / 10;
        if (hi >= HIGH_REALMS.length) return FINAL_REALM;   // 独断万古之后没有境界了
        String name = HIGH_REALMS[hi];
        int layer = (n - 21) % 10;
        return layer == 9 ? name + " 圆满" : name + " " + LAYERS[layer];
    }

    static int realmColor(int n) {
        if (n <= 0) return 0xFF9E9E9E;
        return REALM_COLORS[realmIdx(n)];
    }

    static String realmDesc(int n) {
        if (n <= 0) return "尚未踏上修炼之路";
        return DESCS[realmIdx(n)];
    }

    private static int auraIdx(int n) {
        return realmIdx(n);
    }

    static String nextRealmHint(int n) {
        if (n <= 0) return "再通 1 关，踏入炼气";
        for (int i = 0; i < NEXT_AT.length; i++) {
            if (n < NEXT_AT[i]) {
                int need = NEXT_AT[i] - n;
                boolean last = i == NEXT_AT.length - 1;
                return "再通 " + need + " 关，迈入" + NEXT_NAME[i]
                        + (last ? "——万古之巅" : "");
            }
        }
        return "独断万古，此界之上再无境界";
    }

    // 化神后的柔和呼吸光：光晕 alpha 缓慢往复 + 徽章轻微明暗，不刺眼；离屏即停，不泄漏
    private static void startDivinePulse(View glow, View badge) {
        ObjectAnimator ga = ObjectAnimator.ofFloat(glow, "alpha", 0.10f, 0.45f);
        ga.setDuration(1800);
        ga.setRepeatCount(ValueAnimator.INFINITE);
        ga.setRepeatMode(ValueAnimator.REVERSE);
        ga.setInterpolator(new AccelerateDecelerateInterpolator());
        ObjectAnimator ba = ObjectAnimator.ofFloat(badge, "alpha", 0.88f, 1f);
        ba.setDuration(1800);
        ba.setRepeatCount(ValueAnimator.INFINITE);
        ba.setRepeatMode(ValueAnimator.REVERSE);
        ba.setInterpolator(new AccelerateDecelerateInterpolator());
        final AnimatorSet set = new AnimatorSet();
        set.playTogether(ga, ba);
        badge.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
            @Override
            public void onViewAttachedToWindow(View v) {
            }

            @Override
            public void onViewDetachedFromWindow(View v) {
                set.cancel();
            }
        });
        set.start();
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
