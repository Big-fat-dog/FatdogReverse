package com.fatdog.reverse;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.DecelerateInterpolator;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

// 白天/黑夜主题：默认黑夜；状态持久化。
// 细节：本 App 自带主题，需用 setForceDarkAllowed(false) 阻止系统/MIUI 强制反色，
//      否则"深色模式"会把我们的浅色设计整体打黑。
public class ThemeKit {
    private static final String PREFS = "fatdemo_prefs";
    private static final String KEY_DARK = "dark";

    public static boolean isDark(Context c) {
        return c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_DARK, true);
    }

    public static void setDark(Context c, boolean dark) {
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean(KEY_DARK, dark).apply();
    }

    public static int bg(boolean d) {
        return d ? 0xFF141419 : 0xFFFFFFFF;
    }

    public static int card(boolean d) {
        return d ? 0xFF1F1F26 : 0xFFFFFFFF;
    }

    public static int panel(boolean d) {
        return d ? 0xFF24242B : 0xFFF1F1F5;
    }

    public static int text(boolean d) {
        return d ? 0xFFECECF2 : 0xFF1B1B1F;
    }

    public static int muted(boolean d) {
        return d ? 0xFF9A9AA3 : 0xFF7A7A82;
    }

    private static int hintColor(boolean d) {
        return d ? 0x999A9AA3 : 0x997A7A82;
    }

    // 阻止系统强制反色，改用我们自己的主题
    public static void blockForceDark(Activity a) {
        if (Build.VERSION.SDK_INT >= 29) {
            a.getWindow().getDecorView().setForceDarkAllowed(false);
        }
    }

    public static void recolor(View view, boolean dark) {
        // 按钮(提交/提示/关卡卡)一律不动：它们自带样式(圆角/描边/底纹)，改了会变"白框"
        if (view instanceof EditText) {
            ((EditText) view).setTextColor(text(dark));
            ((EditText) view).setHintTextColor(hintColor(dark));
        } else if (view instanceof TextView && view.getBackground() == null) {
            ((TextView) view).setTextColor(text(dark));
        }
        if (view instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) view;
            for (int i = 0; i < g.getChildCount(); i++) {
                recolor(g.getChildAt(i), dark);
            }
        }
    }

    // 让一个 Activity 的内容区整体套用当前主题（无动画）
    public static void apply(Activity a) {
        blockForceDark(a);
        View content = a.findViewById(android.R.id.content);
        if (content == null) return;
        content.setBackgroundColor(bg(isDark(a)));
        recolor(content, isDark(a));
    }

    // 主界面日夜切换：背景渐变 + 结束后整体上色
    public static void animateToggle(final Activity a, final Runnable done) {
        blockForceDark(a);
        final boolean dark = !isDark(a);
        setDark(a, dark);
        final View content = a.findViewById(android.R.id.content);
        int from = bg(!dark);
        int to = bg(dark);
        ValueAnimator anim = ValueAnimator.ofObject(new ArgbEvaluator(), from, to);
        anim.setDuration(520);
        anim.setInterpolator(new DecelerateInterpolator());
        anim.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator va) {
                content.setBackgroundColor((Integer) va.getAnimatedValue());
            }
        });
        anim.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(android.animation.Animator animation) {
                recolor(content, dark);
                if (done != null) done.run();
            }
        });
        anim.start();
    }
}