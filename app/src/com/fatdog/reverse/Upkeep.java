package com.fatdog.reverse;

import android.app.Activity;
import android.graphics.Typeface;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

/**
 * 太玄之初 · 维护页（KL16-20 共用）。
 *
 * 背景：KL16-20 原设计为"壳行为的语义模拟"（只在 .bss 里分片/回填/抽取一个标记字符串，
 * 没有任何真实加密 DEX），与"脱壳实训"的定位不符，已下架重制。
 *
 * 处置口径：只改"题面 + 入口"，不动游戏规则——
 *   ① 页内直接给出提交答案；
 *   ② 保留答案输入框，输入正确数值即 PassLog.mark() 标记通关（保证 110 关总数可达）；
 *   ③ 不揭晓 flag（留待重制后）。
 *
 * 本页不触发任何旧解密链，也不联网。
 */
public final class Upkeep {

    private Upkeep() {
    }

    /**
     * 构建维护页视图。
     *
     * @param act    宿主 Activity
     * @param banner 关卡横幅资源（R.drawable.level_klNN）
     * @param level  关卡标识（如 "KL16"，同时作为 PassLog 的记录键）
     * @param name   关卡名（如 "破壳新生"）
     * @param answer 直接给出的提交答案（字符串，如 "51495"）
     */
    public static View page(final Activity act, int banner, final String level,
                            String name, final String answer) {
        final boolean dark = ThemeKit.isDark(act);

        LinearLayout box = new LinearLayout(act);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(14), Ui.dp(16), Ui.dp(12));

        TextView title = new TextView(act);
        title.setText("太玄之初 · " + level + "「" + name + "」");
        title.setTextSize(19);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(ThemeKit.text(dark));
        box.addView(title, Ui.wrap(6));

        TextView notice = new TextView(act);
        notice.setText("⚠ 本关维护中，暂不启用\n"
                + "旧设计为「壳行为的语义模拟」，没有真实加密 DEX，与「脱壳实训」定位不符，"
                + "已下架重制。重制完成后将在本页恢复。");
        notice.setTextSize(14);
        notice.setGravity(Gravity.CENTER);
        notice.setLineSpacing(Ui.dp(3), 1f);
        notice.setTextColor(ThemeKit.muted(dark));
        box.addView(notice, Ui.fullWidth(12));

        TextView give = new TextView(act);
        give.setText("作为补偿，本关答案直接给出：\n提交答案 " + answer);
        give.setTextSize(16);
        give.setTypeface(Typeface.DEFAULT_BOLD);
        give.setGravity(Gravity.CENTER);
        give.setTextColor(0xFFFB7299);
        give.setLineSpacing(Ui.dp(3), 1f);
        box.addView(give, Ui.fullWidth(16));

        final EditText ansIn = new EditText(act);
        ansIn.setHint("输入提交答案");
        ansIn.setInputType(InputType.TYPE_CLASS_NUMBER);
        box.addView(ansIn, Ui.fullWidth(16));

        Button subBtn = new Button(act);
        subBtn.setText("提交");
        Ui.styleButton(subBtn);
        box.addView(subBtn, Ui.wrap(12));

        box.addView(Ui.banner(act, banner, 150));

        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String s = ansIn.getText().toString().trim();
                if (s.equals(answer)) {
                    PassLog.mark(act, level);
                    Celebration.show(act, level + " 已记录");
                } else {
                    Toast.makeText(act, "答案不对，再核对一下。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        return Ui.wrapScroll(box);
    }
}
