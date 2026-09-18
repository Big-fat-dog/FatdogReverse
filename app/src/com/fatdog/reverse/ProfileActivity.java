package com.fatdog.reverse;

import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.BlurMaskFilter;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.LinearGradient;
import android.graphics.Shader;
import android.view.animation.LinearInterpolator;
import android.os.Bundle;
import android.util.SparseArray;
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

// 个人主页：顶部"传送带"式分类条（基本情况 / 太古禁地 / 神念自察 / 昔日枷锁 / 前世今生），可横向滑动；
// 下方内容随分类切换。基本情况 = 头像 + 境界 + 修仙进度；右上角昼夜切换；背景图。
public class ProfileActivity extends Activity {
    private static final int TOTAL_LEVELS = 98;   // L1-L47 + L48-L53 + KL1-KL45 + KKL1-KKL5（LEVEL_IDS 数组长度）
    // 炼气~元婴：每 5 关一层（1-20）；化神起：每 10 关一个大境界，第 10 层为"圆满"；
    // 高阶四境之后是终点"独断万古"——通关数再多也停在它上面。
    private static final String[] BIG_REALMS = {"炼气", "筑基", "金丹", "元婴"};
    private static final String[] HIGH_REALMS = {"化神", "洞虚", "归墟", "无量", "归一", "无极", "永恒"};
    private static final String FINAL_REALM = "独断万古";
    private static final String[] LAYERS = {
            "一层", "二层", "三层", "四层", "五层", "六层", "七层", "八层", "九层"
    };
    // 下一个大境界的门槛（通关数）与名称，nextRealmHint 用
    private static final int[] NEXT_AT = {6, 11, 16, 21, 31, 41, 51, 61, 71, 81, 91};
    private static final String[] NEXT_NAME = {"筑基", "金丹", "元婴", "化神", "洞虚", "归墟", "无量", "归一", "无极", "永恒", FINAL_REALM};
    private static final int[] REALM_COLORS = {
            0xFF67C23A, 0xFF409EFF, 0xFFE6A23C, 0xFFB37FEB,
            0xFFFB7299, 0xFF36CFC9, 0xFF2F54EB, 0xFFFADB14,
            0xFF00B5AD, 0xFF722ED1, 0xFFB8965A, 0xFFB8965A
    };
    private static final String[] DESCS = {
            "引气入体，初窥门径",
            "筑基成功，道基已固",
            "金丹结成，脱胎换骨",
            "元婴出窍，遨游天地",
            "化神大能，一念千里",
            "洞虚观世，勘破虚妄",
            "万法归墟，百川朝宗",
            "无量无边，不可思议",
            "万法归一，大道至简",
            "无极生太极，无穷无尽",
            "永恒不灭，岁月成灰",
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
            "✦ 大道至简，万法归一",
            "✦ 太极轮转，无穷无尽",
            "✦ 永恒之光，岁月成灰",
            "✦ 万古长夜，我为天明",
    };
    private static final String[] CAT_NAMES = {"基本情况", "太古禁地", "神念自察", "昔日枷锁", "前世今生"};
    private static final int[] CAT_ICONS = {R.drawable.ic_tab_profile, R.drawable.ic_forbidden, R.drawable.ic_eye, R.drawable.ic_lock, R.drawable.ic_star};
    private static final int[] CAT_COLORS = {0xFFFB7299, 0xFFFB7299, 0xFF409EFF, 0xFF00BFA5, 0xFFE6A23C};

    private static final int REBORN_INDEX = 4;

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

        final View[] pages = new View[5];
        pages[0] = buildBasicInfo(ctx, avatarClick);
        pages[1] = ForbiddenLandActivity.buildLandView((Activity) ctx);
        pages[2] = DivineReflectionActivity.buildReflectionView((Activity) ctx);
        pages[3] = buildKunlunPlaceholder(ctx);
        pages[4] = PastLifePage.buildPage(ctx);
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
                    // 太古禁地 / 昔日枷锁默认开放，无需通关数门禁
                    if (idx == REBORN_INDEX) {
                        PastLifePage.enter(ctx, new Runnable() {
                            @Override
                            public void run() {
                                selectPage(ctx, idx, chips, pages);
                            }
                        });
                    } else {
                        selectPage(ctx, idx, chips, pages);
                    }
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
        box.setClipChildren(false);
        box.setClipToPadding(false);

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

        // 境界徽章（化神起带文字描边光晕；终点境界为深空鎏金渐变）
        boolean finale = isFinalRealm(n);
        boolean divineGlow = hasDivineGlow(n);
        View realm;
        LinearLayout.LayoutParams realmLp;
        if (divineGlow) {
            GlowTextView gv = new GlowTextView(ctx, realmColor(n), finale);
            gv.setText(realmName(n));
            gv.setTextSize(30);
            gv.setTypeface(Typeface.DEFAULT_BOLD);
            gv.setTextColor(Color.WHITE);
            gv.setGravity(Gravity.CENTER);
            // 化神后取消底部徽章，让动态字体（彩色描边 + 呼吸辉光）成为主角。
            // 加大内边距给外围辉光留出余量，避免软辉光被裁切；底部多留间距不压下方文字。
            gv.setPadding(dp(ctx, 28), dp(ctx, 22), dp(ctx, 28), dp(ctx, 22));
            realm = gv;
            realmLp = Ui.wrap(12);
            realmLp.bottomMargin = dp(ctx, 22);
            box.addView(realm, realmLp);
            startDivinePulse(gv);
        } else {
            TextView tv = new TextView(ctx);
            tv.setText(realmName(n));
            tv.setTextSize(22);
            tv.setTypeface(Typeface.DEFAULT_BOLD);
            tv.setTextColor(Color.WHITE);
            tv.setGravity(Gravity.CENTER);
            GradientDrawable badge = new GradientDrawable();
            badge.setShape(GradientDrawable.RECTANGLE);
            badge.setCornerRadius(dp(ctx, 24f));
            badge.setColor(realmColor(n));
            badge.setStroke(dp(ctx, 2f), 0x44FFFFFF);
            tv.setBackground(badge);
            tv.setPadding(dp(ctx, 20), dp(ctx, 8), dp(ctx, 20), dp(ctx, 8));
            realm = tv;
            realmLp = Ui.wrap(12);
            realmLp.bottomMargin = dp(ctx, 10);
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


    /* 昔日枷锁：已通关的秘境关卡留档于此，点击进入小说阅读器 */
    private static View buildKunlunPlaceholder(final Context ctx) {
        ScrollView scroll = new ScrollView(ctx);
        LinearLayout col = new LinearLayout(ctx);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(ctx,20), dp(ctx,16), dp(ctx,20), dp(ctx,24));
        TextView tip = new TextView(ctx);
        tip.setText("昔日枷锁，皆已可回首。\n通关天地秘境关卡后，此处将浮现属于你的故事。");
        tip.setTextSize(13); tip.setTextColor(ThemeKit.muted(ThemeKit.isDark(ctx)));
        tip.setGravity(Gravity.CENTER); tip.setPadding(0, dp(ctx,30), 0, dp(ctx,20));
        col.addView(tip);

        String[][] zones = {
            {"—— 昆仑山 ——", "KL1", "山门", "KL2", "引雷桩", "KL3", "渡鸦桥", "KL4", "冰裂缝", "KL5", "登顶"},
            {"—— 流沙河 ——", "KL6", "冰封之钥", "KL7", "裂魂之匣", "KL8", "幽泉之眼", "KL9", "天罡北斗", "KL10", "万象归一"},
            {"—— 幽冥海 ——", "KL11", "偷梁换柱", "KL12", "移花接木", "KL13", "声东击西", "KL14", "偷天换日", "KL15", "万法归宗"},
            {"—— 太玄之初 ——", "KL16", "破壳新生", "KL17", "金蝉脱壳", "KL18", "乾坤迷阵", "KL19", "虚空造化", "KL20", "破壁飞升"},
            {"—— 太玄之初 · 壳 ——", "KKL1", "玄冥渊", "KKL2", "万剑冢", "KKL3", "断魂谷", "KKL4", "锁妖塔", "KKL5", "诛仙台"},
            {"—— 扶桑树 ——", "KL21", "枯叶听风", "KL22", "落影寻痕", "KL23", "照妖显形", "KL24", "冰鉴悬镜", "KL25", "暮雾锁听", "KL26", "暮霭沉沉", "KL27", "轻纱覆影", "KL28", "雪落无痕"},
            {"—— 天机阁 ——", "KL29", "暗流涌动", "KL30", "天机织锦"},
            {"—— 碧落天 ——", "KL36", "云中锦书", "KL37", "风中鸢尾", "KL38", "雾里观花", "KL39", "月下独酌", "KL40", "星河倒影"},
            {"—— 须弥界 ——", "KL41", "浅滩拾贝", "KL42", "沙中藏贝", "KL43", "桥上听风", "KL44", "暗流涌动", "KL45", "深渊合璧"}
        };

        for (String[] zone : zones) {
            TextView zoneTitle = new TextView(ctx);
            zoneTitle.setText(zone[0]);
            zoneTitle.setTextSize(12); zoneTitle.setTextColor(0xFFFB7299);
            zoneTitle.setGravity(Gravity.CENTER);
            zoneTitle.setPadding(0, dp(ctx,10), 0, dp(ctx,4));
            col.addView(zoneTitle);
            for (int j = 1; j < zone.length; j += 2) {
                final String levelId = zone[j];
                final String name = zone[j + 1];
                boolean open = PassLog.isDone(ctx, levelId);
                LinearLayout row = new LinearLayout(ctx);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setGravity(Gravity.CENTER_VERTICAL);
                row.setPadding(dp(ctx,10), dp(ctx,12), dp(ctx,10), dp(ctx,12));
                GradientDrawable g = new GradientDrawable();
                g.setCornerRadius(dp(ctx,10));
                g.setColor(open ? 0x33FB7299 : (ThemeKit.isDark(ctx) ? 0xCC24242B : 0x22EEEEEE));
                row.setBackground(g);
                TextView t = new TextView(ctx);
                t.setText((open ? "✦ " : "🔒 ") + levelId + " · " + name);
                t.setTextSize(15); t.setTypeface(Typeface.DEFAULT_BOLD);
                t.setTextColor(open ? 0xFFFB7299 : (ThemeKit.isDark(ctx) ? 0xFF77777F : 0xFFAAAAAA));
                row.addView(t, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
                if (open) {
                    TextView arrow = new TextView(ctx);
                    arrow.setText("›");
                    arrow.setTextSize(18);
                    arrow.setTextColor(0xFFFB7299);
                    row.addView(arrow);
                    row.setOnClickListener(new View.OnClickListener() {
                        @Override public void onClick(View v) {
                            Class<?> target = "KL36".equals(levelId) ? scrollActivity.class : "KL38".equals(levelId) ? hazeActivity.class : "KL41".equals(levelId) ? surfActivity.class : "KL42".equals(levelId) ? reefActivity.class : "KL43".equals(levelId) ? coralActivity.class : "KL44".equals(levelId) ? pearlActivity.class : "KL45".equals(levelId) ? hybridActivity.class : DivineStoryActivity.class;
                            Intent intent = new Intent(ctx, target);
                            intent.putExtra("level", levelId);
                            intent.putExtra("title", name);
                            ((android.app.Activity) ctx).startActivity(intent);
                        }
                    });
                }
                LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
                mlp.topMargin = dp(ctx, 6);
                col.addView(row, mlp);
            }
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

    // 化神后的神辉特效：光晕柔和呼吸、半径随呼吸向外逸散（神辉逸散感）；
    // 所有神辉境界都有缓慢色相流动（流光），终点境界「独断万古」额外启用满幅彩虹流光。
    private static void startDivinePulse(final GlowTextView gv) {
        // 1) 神辉呼吸：由暗到亮缓慢往复（0.2→1，留底光、似呼吸），并驱动光晕半径涨落
        ObjectAnimator a = ObjectAnimator.ofFloat(gv, "glowIntensity", 0.2f, 1f);
        a.setDuration(2200);
        a.setRepeatCount(ValueAnimator.INFINITE);
        a.setRepeatMode(ValueAnimator.REVERSE);
        a.setInterpolator(new AccelerateDecelerateInterpolator());
        a.start();

        // 2) 流光：所有境界都做缓慢色相流动（来回摆荡，柔和流光），不刺眼
        ObjectAnimator d = ObjectAnimator.ofFloat(gv, "hueDrift", 0f, 1f);
        d.setDuration(8000);
        d.setRepeatCount(ValueAnimator.INFINITE);
        d.setRepeatMode(ValueAnimator.REVERSE);
        d.setInterpolator(new LinearInterpolator());
        d.start();

        // 3) 终点境界再叠加满幅彩虹色相循环（炫彩流光）
        if (gv.isRainbow()) {
            ObjectAnimator h = ObjectAnimator.ofFloat(gv, "hueShift", 0f, 1f);
            h.setDuration(5200);
            h.setRepeatCount(ValueAnimator.INFINITE);
            h.setInterpolator(new LinearInterpolator());
            h.start();
            final ObjectAnimator fh = h;
            gv.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
                @Override public void onViewAttachedToWindow(View v) {}
                @Override public void onViewDetachedFromWindow(View v) {
                    a.cancel(); d.cancel(); fh.cancel();
                }
            });
        } else {
            gv.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
                @Override public void onViewAttachedToWindow(View v) {}
                @Override public void onViewDetachedFromWindow(View v) {
                    a.cancel(); d.cancel();
                }
            });
        }
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

    /**
     * 化神+境界动态字体（无底部徽章，字本身就是主角），全部手动绘制、绝不调用 super：
     *  - 周围神辉：淡色 + 高斯模糊填充（内核柔光 + 外层大半径向外逸散、包裹整字）；
     *    半径与透明度都随 glowIntensity 呼吸涨落 → 「呼吸明灭 + 向外逸散」并存；
     *  - 流光：所有神辉境界都有缓慢色相摆荡（hueDrift），终点境「独断万古」再叠加满幅彩虹流光（hueShift）；
     *  - 字形填充：普通境专属色亮渐变（高明度保证清晰可读）、终点境彩虹流光；
     *  - 彩色描边：宽 2dp 的淡色细勾边，勾轮廓而不糊字。
     * 三层均使用同一 (cx,cy)；辅助画笔 glowPaint/strokePaint 的字号与字体每帧同步自 tp
     * （否则其默认 textSize=0 会把辉光/描边退化成"挤在一起的发光小色块"）。
     * 模糊半径按 px 缓存（BLUR_CACHE），避免每帧 new BlurMaskFilter 造成 GC 抖动。
     */
    private static class GlowTextView extends TextView {
        private final Paint glowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);    // 周围神辉（模糊填充，柔和逸散）
        private final Paint strokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);  // 彩色描边
        private float glowIntensity = 0f;
        private float hueShift = 0f;       // 0..1 映射到色相 0..360 度（仅终点境界满幅彩虹）
        private float hueDrift = 0f;       // 0..1 缓慢摆荡，所有境界共用的"流光"色相偏移
        private final float baseHue;       // 本境界专属色相（0..360），由徽章底色推导
        private final float secondHue;     // 同色系第二色相，制造双色字体
        private final boolean rainbow;     // true=终点境界，彩虹流光

        // 模糊半径缓存：避免每帧 new BlurMaskFilter 造成 GC 抖动（按 px 半径缓存）
        private static final SparseArray<BlurMaskFilter> BLUR_CACHE = new SparseArray<>();
        private static BlurMaskFilter blurPx(int px) {
            BlurMaskFilter f = BLUR_CACHE.get(px);
            if (f == null) {
                f = new BlurMaskFilter(Math.max(px, 1), BlurMaskFilter.Blur.NORMAL);
                BLUR_CACHE.put(px, f);
            }
            return f;
        }

        GlowTextView(Context ctx, int color, boolean rainbow) {
            super(ctx);
            this.rainbow = rainbow;
            float[] hsv = new float[3];
            android.graphics.Color.colorToHSV(color, hsv);
            this.baseHue = hsv[0];
            this.secondHue = hsv[0] + 34f;   // 临近色相，同色系双色
            // 软件层渲染，使 BlurMaskFilter 生效（硬件加速会忽略 maskFilter）
            setLayerType(View.LAYER_TYPE_SOFTWARE, null);
            glowPaint.setStyle(Paint.Style.FILL);   // 模糊填充 → 真正柔和的逸散光晕
            glowPaint.setTextAlign(Paint.Align.CENTER);
            strokePaint.setStyle(Paint.Style.STROKE);
            strokePaint.setTextAlign(Paint.Align.CENTER);
        }

        boolean isRainbow() { return rainbow; }

        /** ObjectAnimator 动画目标属性 */
        public float getGlowIntensity() { return glowIntensity; }
        public void setGlowIntensity(float v) { glowIntensity = v; invalidate(); }
        public float getHueShift() { return hueShift; }
        public void setHueShift(float v) { hueShift = v; invalidate(); }
        public float getHueDrift() { return hueDrift; }
        public void setHueDrift(float v) { hueDrift = v; invalidate(); }

        /** HSV→带透明度的颜色，色相自动归一到 [0,360) */
        private static int hsv(float hh, float s, float vv, float aa) {
            hh = ((hh % 360f) + 360f) % 360f;
            return android.graphics.Color.HSVToColor(
                    (int) (Math.min(Math.max(aa, 0f), 1f) * 255), new float[]{hh, s, vv});
        }

        @Override
        protected void onDraw(Canvas c) {
            String t = getText().toString();
            if (t == null || t.length() == 0) { super.onDraw(c); return; }
            float cx = getWidth() / 2f;
            float cy = getHeight() / 2f - (getPaint().ascent() + getPaint().descent()) / 2f;
            Paint tp = getPaint();
            Shader oldShader = tp.getShader();
            Paint.Style oldStyle = tp.getStyle();
            Paint.Align oldAlign = tp.getTextAlign();

            // 关键：glowPaint / strokePaint 是新建的 Paint，默认 textSize=0，
            // 不同步的话辉光与描边会缩成极小字（表现为"中间挤在一起的发光小色块"）。
            // 必须与正文画笔 tp 保持同一字号与字体，特效才会正确包裹在「化神一层」大字外面。
            glowPaint.setTextSize(tp.getTextSize());
            glowPaint.setTypeface(tp.getTypeface());
            strokePaint.setTextSize(tp.getTextSize());
            strokePaint.setTypeface(tp.getTypeface());

            // 本帧配色：所有境界都带缓慢"流光"色相偏移（hueDrift 来回摆荡），
            // 终点境在此之上再叠加满幅彩虹流光（hueShift）。
            int glowCol, strokeCol, fillA, fillB;
            float flow;   // 当前流光色相偏移（度）
            if (rainbow) {
                flow = hueShift * 360f;                 // 满幅彩虹流光
                glowCol   = hsv(flow,        0.50f, 1f, 1f);   // 淡色辉光
                strokeCol = hsv(flow + 40f,  0.70f, 1f, 1f);   // 淡描边
                fillA     = hsv(flow,        0.80f, 1f, 1f);   // 亮填充
                fillB     = hsv(flow + 180f, 0.80f, 1f, 1f);
            } else {
                flow = baseHue + (hueDrift * 2f - 1f) * 40f;   // ±40° 柔和摆荡流光（保留本境色相）
                glowCol   = hsv(flow,   0.38f, 1f, 1f);        // 淡色辉光
                strokeCol = hsv(flow,   0.55f, 1f, 1f);        // 淡描边
                fillA     = hsv(flow,   0.55f, 0.98f, 1f);     // 亮填充，字清晰可读
                fillB     = hsv(flow + (secondHue - baseHue), 0.50f, 0.92f, 1f);
            }

            // 1) 周围神辉：淡色模糊填充，内外两层；
            //    半径随 glowIntensity 呼吸涨落（向外逸散/回收），透明度同步呼吸 → "呼吸 + 逸散"并存
            if (glowIntensity > 0.01f) {
                float g = glowIntensity;                  // 0.2..1，呼吸明灭
                float baseR = rainbow ? 30f : 24f;
                int rOuter = (int) (dp(getContext(), baseR * (0.55f + 0.65f * g)));
                int rInner = (int) (dp(getContext(), baseR * 0.45f * (0.7f + 0.5f * g)));
                glowPaint.setColor(glowCol);
                glowPaint.setStyle(Paint.Style.FILL);
                // 外层：大半径模糊向外逸散、包裹整字，随呼吸收放
                glowPaint.setMaskFilter(blurPx(rOuter));
                glowPaint.setAlpha((int) (95f * g));
                c.drawText(t, cx, cy, glowPaint);
                // 内层：小半径模糊贴着字的柔光，随呼吸明灭
                glowPaint.setMaskFilter(blurPx(rInner));
                glowPaint.setAlpha((int) (165f * g));
                c.drawText(t, cx, cy, glowPaint);
                glowPaint.setMaskFilter(null);
            }

            // 2) 字形填充（同 (cx,cy)，与辉光/描边完全对齐，不调用 super）
            int[] cols;
            float[] pos;
            if (rainbow) {
                cols = new int[6];
                pos = new float[]{0f, 0.2f, 0.4f, 0.6f, 0.8f, 1f};
                for (int i = 0; i < 6; i++) cols[i] = hsv(flow + i * 60f, 0.85f, 1f, 1f);
            } else {
                cols = new int[]{fillA, fillB};
                pos = null;
            }
            tp.setStyle(Paint.Style.FILL);
            tp.setTextAlign(Paint.Align.CENTER);
            tp.setShader(new LinearGradient(0, 0, getWidth(), 0, cols, pos, Shader.TileMode.CLAMP));
            c.drawText(t, cx, cy, tp);

            // 3) 彩色描边：细勾边压在字形边缘（宽 2dp、淡色），勾出轮廓但不糊字
            strokePaint.setStrokeWidth(dp(getContext(), 2f));
            strokePaint.setColor(strokeCol);
            c.drawText(t, cx, cy, strokePaint);

            // 还原 TextView 默认画笔状态
            tp.setStyle(oldStyle);
            tp.setTextAlign(oldAlign);
            tp.setShader(oldShader);
        }
    }
}
