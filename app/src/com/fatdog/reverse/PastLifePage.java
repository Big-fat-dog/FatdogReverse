package com.fatdog.reverse;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

// 前世今生：个人主页内的进度修复页。进入需密令 Fatdog；
// 页内点一次补回该关记录，再点一次撤销该关记录。
final class PastLifePage {
    private static final String PASSWORD = "Fatdog";
    private static boolean unlocked = false;

    private PastLifePage() {}

    static void enter(final Context ctx, final Runnable onUnlocked) {
        if (unlocked) {
            onUnlocked.run();
            return;
        }
        if (!(ctx instanceof Activity)) return;
        final Activity act = (Activity) ctx;
        boolean dark = ThemeKit.isDark(ctx);
        final Dialog dlg = new Dialog(act);
        dlg.requestWindowFeature(Window.FEATURE_NO_TITLE);

        LinearLayout card = new LinearLayout(act);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(ctx, 22), dp(ctx, 20), dp(ctx, 22), dp(ctx, 16));
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(ctx, 18));
        bg.setColor(dark ? 0xF222222A : 0xFFF2F2F7);
        card.setBackground(bg);

        TextView title = new TextView(act);
        title.setText("前 世 今 生");
        title.setTextSize(19);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(0xFFE6A23C);
        title.setGravity(Gravity.CENTER);
        card.addView(title, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        TextView message = new TextView(act);
        message.setText("前尘散尽者，可凭此令重拾旧忆。");
        message.setTextSize(13);
        message.setTextColor(dark ? 0xFFB9B9C2 : 0xFF666670);
        message.setGravity(Gravity.CENTER);
        message.setPadding(0, dp(ctx, 10), 0, dp(ctx, 4));
        card.addView(message, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        final EditText input = new EditText(act);
        input.setHint("输入命令");
        input.setTextColor(dark ? 0xFFECECF2 : 0xFF33333B);
        input.setHintTextColor(0xFF77777F);
        GradientDrawable eb = new GradientDrawable();
        eb.setCornerRadius(dp(ctx, 10));
        eb.setColor(dark ? 0xFF1B1B22 : 0xFFECECF0);
        input.setBackground(eb);
        input.setPadding(dp(ctx, 12), dp(ctx, 10), dp(ctx, 12), dp(ctx, 10));
        LinearLayout.LayoutParams ilp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        ilp.topMargin = dp(ctx, 12);
        card.addView(input, ilp);

        TextView ok = new TextView(act);
        ok.setText("持 令 进 入");
        ok.setTextSize(15);
        ok.setTypeface(Typeface.DEFAULT_BOLD);
        ok.setTextColor(Color.WHITE);
        ok.setGravity(Gravity.CENTER);
        GradientDrawable ob = new GradientDrawable();
        ob.setCornerRadius(dp(ctx, 24));
        ob.setColor(0xFFFB7299);
        ok.setBackground(ob);
        LinearLayout.LayoutParams olp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(ctx, 44));
        olp.topMargin = dp(ctx, 16);
        card.addView(ok, olp);
        ok.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (PASSWORD.equals(input.getText().toString().trim())) {
                    unlocked = true;
                    dlg.dismiss();
                    onUnlocked.run();
                } else {
                    Toast.makeText(ctx, "命令有误", Toast.LENGTH_SHORT).show();
                }
            }
        });

        TextView cancel = new TextView(act);
        cancel.setText("暂不回溯");
        cancel.setTextSize(13);
        cancel.setTextColor(0xFF8A8A92);
        cancel.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        clp.topMargin = dp(ctx, 10);
        card.addView(cancel, clp);
        cancel.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dlg.dismiss();
            }
        });

        dlg.setContentView(card);
        dlg.getWindow().setBackgroundDrawable(new ColorDrawable(0x00000000));
        dlg.show();
    }


    static View buildPage(final Context ctx) {
        boolean dark = ThemeKit.isDark(ctx);
        ScrollView scroll = new ScrollView(ctx);
        LinearLayout col = new LinearLayout(ctx);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(ctx, 14), dp(ctx, 4), dp(ctx, 14), dp(ctx, 24));

        TextView title = new TextView(ctx);
        title.setText("前 世 今 生");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(0xFFE6A23C);
        title.setGravity(Gravity.CENTER);
        col.addView(title, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        TextView tip = new TextView(ctx);
        tip.setText("点一次补回，再点一次撤销");
        tip.setTextSize(12);
        tip.setTextColor(ThemeKit.muted(dark));
        tip.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams tipLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        tipLp.topMargin = dp(ctx, 2);
        col.addView(tip, tipLp);

        addRange(ctx, col, "主卷", 0xFF409EFF, "L", 1, 48);
        addRange(ctx, col, "天地秘境", 0xFF00BFA5, "KL", 1, 30);
        addRange(ctx, col, "太玄之初", 0xFFB37FEB, "KKL", 1, 3);

        scroll.addView(col);
        return scroll;
    }

    private static void addRange(final Context ctx, final LinearLayout col,
                                 final String name, final int accent,
                                 final String prefix, final int from, final int to) {
        TextView head = new TextView(ctx);
        head.setText(name);
        head.setTextSize(12);
        head.setTypeface(Typeface.DEFAULT_BOLD);
        head.setTextColor(accent);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        hp.topMargin = dp(ctx, 10);
        hp.leftMargin = dp(ctx, 4);
        col.addView(head, hp);

        for (int i = from; i <= to; i += 4) {
            LinearLayout row = new LinearLayout(ctx);
            row.setOrientation(LinearLayout.HORIZONTAL);
            for (int j = i; j <= Math.min(i + 3, to); j++) {
                LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(
                        0, dp(ctx, 46), 1f);
                cp.setMargins(dp(ctx, 2), dp(ctx, 2), dp(ctx, 2), dp(ctx, 2));
                row.addView(buildCell(ctx, prefix + j), cp);
            }
            col.addView(row, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        }
    }

    private static View buildCell(final Context ctx, final String id) {
        boolean dark = ThemeKit.isDark(ctx);
        boolean done = PassLog.isDone(ctx, id);
        final int idleBg = dark ? 0xFF24242B : 0xFFF1F1F4;
        final int idleText = dark ? 0xFFD8D8E0 : 0xFF3A3A42;

        final LinearLayout cell = new LinearLayout(ctx);
        cell.setOrientation(LinearLayout.VERTICAL);
        cell.setGravity(Gravity.CENTER);
        final GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(ctx, 10));
        bg.setColor(done ? 0xFFFB7299 : idleBg);
        bg.setStroke(dp(ctx, 1), done ? 0x55FFFFFF : (dark ? 0x22444444 : 0x22000000));
        cell.setBackground(bg);

        final TextView tv = new TextView(ctx);
        tv.setText(done ? "✦ " + id : id);
        tv.setTextSize(12);
        tv.setTypeface(Typeface.DEFAULT_BOLD);
        tv.setGravity(Gravity.CENTER);
        tv.setSingleLine(true);
        tv.setTextColor(done ? Color.WHITE : idleText);
        tv.setIncludeFontPadding(false);
        cell.addView(tv, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.MATCH_PARENT));

        cell.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (PassLog.isDone(ctx, id)) {
                    PassLog.unmark(ctx, id);
                    bg.setColor(idleBg);
                    bg.setStroke(dp(ctx, 1), dark ? 0x22444444 : 0x22000000);
                    tv.setText(id);
                    tv.setTextColor(idleText);
                    Toast.makeText(ctx, id + " 已撤销", Toast.LENGTH_SHORT).show();
                } else {
                    PassLog.mark(ctx, id);
                    bg.setColor(0xFFFB7299);
                    bg.setStroke(dp(ctx, 1), 0x55FFFFFF);
                    tv.setText("✦ " + id);
                    tv.setTextColor(Color.WHITE);
                    Toast.makeText(ctx, id + " 已通关", Toast.LENGTH_SHORT).show();
                }
            }
        });
        return cell;
    }

    private static int dp(Context c, float v) {
        return (int) (v * c.getResources().getDisplayMetrics().density + 0.5f);
    }
}
