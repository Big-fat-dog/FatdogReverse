package com.fatdog.reverse;

import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
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

// 个人主页：顶部"传送带"式分类条（基本情况 / 太古禁地 / 神念自察 / 昔日枷锁 / 前世今生），可横向滑动；
// 下方内容随分类切换。基本情况 = 头像 + 境界 + 修仙进度；右上角昼夜切换；背景图。
public class ProfileActivity extends Activity {
    private static final int TOTAL_LEVELS = 94;   // L1-L47 + L48-L53 + KL1-KL41 + KKL1-KKL5（LEVEL_IDS 数组长度）
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
            GlowTextView gv = new GlowTextView(ctx, realmColor(n));
            gv.setText(realmName(n));
            gv.setTextSize(22);
            gv.setTypeface(Typeface.DEFAULT_BOLD);
            gv.setTextColor(Color.WHITE);
            gv.setGravity(Gravity.CENTER);
            if (finale) {
                GradientDrawable badge = new GradientDrawable();
                badge.setShape(GradientDrawable.RECTANGLE);
                badge.setCornerRadius(dp(ctx, 24f));
                badge.setColors(FINAL_BADGE_COLORS);
                badge.setOrientation(GradientDrawable.Orientation.TL_BR);
                badge.setStroke(dp(ctx, 2f), FINAL_EDGE_COLOR);
                gv.setBackground(badge);
                gv.setGlowColor(FINAL_GLOW_COLOR);
            } else {
                GradientDrawable badge = new GradientDrawable();
                badge.setShape(GradientDrawable.RECTANGLE);
                badge.setCornerRadius(dp(ctx, 24f));
                badge.setColor(realmColor(n));
                badge.setStroke(dp(ctx, 2f), 0x44FFFFFF);
                gv.setBackground(badge);
            }
            gv.setPadding(dp(ctx, 20), dp(ctx, 8), dp(ctx, 20), dp(ctx, 8));
            realm = gv;
            realmLp = Ui.wrap(12);
            realmLp.bottomMargin = dp(ctx, 10);
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
            {"—— 须弥界 ——", "KL41", "纸上谈兵"}
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
                            Class<?> target = "KL36".equals(levelId) ? scrollActivity.class : "KL38".equals(levelId) ? hazeActivity.class : "KL41".equals(levelId) ? tacticActivity.class : DivineStoryActivity.class;
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

    // 化神后的文字描边呼吸光：光晕强度缓慢往复；离屏即停，不泄漏
    private static void startDivinePulse(final GlowTextView gv) {
        ObjectAnimator a = ObjectAnimator.ofFloat(gv, "glowIntensity", 0f, 1f);
        a.setDuration(1800);
        a.setRepeatCount(ValueAnimator.INFINITE);
        a.setRepeatMode(ValueAnimator.REVERSE);
        a.setInterpolator(new AccelerateDecelerateInterpolator());
        a.start();
        gv.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
            @Override public void onViewAttachedToWindow(View v) {}
            @Override public void onViewDetachedFromWindow(View v) { a.cancel(); }
        });
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

    /** 化神+境界徽章：文字外围多层半透明描边产生炫彩呼吸光晕 */
    private static class GlowTextView extends TextView {
        private final Paint glowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final int baseGlowColor;
        private float glowIntensity = 0f;

        GlowTextView(Context ctx, int color) {
            super(ctx);
            baseGlowColor = color;
            glowPaint.setStyle(Paint.Style.STROKE);
            glowPaint.setTextAlign(Paint.Align.CENTER);
        }

        void setGlowColor(int c) { glowPaint.setColor(c); }

        /** ObjectAnimator ofFloat 动画目标属性 */
        public float getGlowIntensity() { return glowIntensity; }
        public void setGlowIntensity(float v) {
            glowIntensity = v;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas c) {
            if (glowIntensity > 0.01f) {
                String t = getText().toString();
                float cx = getWidth() / 2f;
                float cy = getHeight() / 2f - (getPaint().ascent() + getPaint().descent()) / 2f;
                int baseA = (baseGlowColor >> 24) & 0xFF;
                float[] hsl = new float[3];
                android.graphics.Color.colorToHSV(baseGlowColor, hsl);
                // 五层描边，由粗到细、由暗到亮
                float[][] layers = {
                    {6f, 0.06f, 12f},
                    {4f, 0.10f, 10f},
                    {3f, 0.18f,  6f},
                    {2f, 0.30f,  3f},
                    {1f, 0.50f,  0f},
                };
                for (float[] l : layers) {
                    hsl[1] = l[2] == 0f ? 0.3f : Math.min(hsl[1] + 0.1f, 1f);
                    glowPaint.setStrokeWidth(l[0]);
                    int a = (int)(baseA * l[1] * glowIntensity);
                    int rgb = android.graphics.Color.HSVToColor(Math.min(a, 255), hsl);
                    glowPaint.setColor(rgb);
                    c.drawText(t, cx, cy, glowPaint);
                }
            }
            super.onDraw(c);
        }
    }
}
