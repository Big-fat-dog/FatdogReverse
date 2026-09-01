package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * KL14 偷天换日（★★★★ 多 so 交叉验证）。
 *
 * 三 so 交叉验证：libm13a 算 digest_A，libm13b 算 digest_B，
 * libm13c 拼装 A‖B 再 hash 得最终答案。patch 任一 so 即全链失效。
 * 答案只能靠逆向还原，UI 不暴露任何中间值/期望值。
 */
public class v51Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL14 · 偷天换日（★★★★）\n\n"
                + "libm13a 算 digest_A，libm13b 算 digest_B，\n"
                + "libm13c 拼装 A‖B 再 hash 得最终答案。\n\n"
                + "三个 so 交叉验证，patch 任一即全链失效。\n"
                + "本关不暴露任何中间值或期望值，答案只能靠逆向还原。");
        tv.setGravity(Gravity.CENTER);
        tv.setTextColor(Color.WHITE);
        tv.setTextSize(15);
        root.addView(tv, Ui.wrap(6));

        final EditText ansBox = new EditText(this);
        ansBox.setHint("输入答案（32位 hex）");
        ansBox.setTextColor(Color.WHITE);
        ansBox.setTypeface(android.graphics.Typeface.MONOSPACE);
        ansBox.setBackgroundColor(0x33FFFFFF);
        int p = Ui.dp(10);
        ansBox.setPadding(p, p, p, p);
        root.addView(ansBox, Ui.fullWidth(10));

        Button submit = new Button(this);
        submit.setText("提交");
        Ui.styleButton(submit);
        submit.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansBox.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(v51Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                if (ans.equals(Zn.nativeCombineFromC())) {
                    Celebration.show(v51Activity.this, "FLAG_18_KL14{mesh_of_three}");
                    PassLog.mark(v51Activity.this, "KL14");
                } else {
                    Toast.makeText(v51Activity.this, "答案不对，再逆向分析一遍。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(submit, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(v51Activity.this)
                        .setTitle("提示")
                        .setMessage("三 so 通过 dlsym 交叉调用：libm13a/b/c 谁算 A、谁算 B、谁拼装 hash？\n"
                                + "正解方向：IDA/Ghidra 顺 dlsym 调用链还原三段算法与拼接顺序，或 Frida hook 三个导出函数拿返回值对拍。\n"
                                + "patch 任一 so 即全链失效——这不是简单替换一个函数能过的。")
                        .setPositiveButton("好的", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        Button back = new Button(this);
        back.setText("返回");
        Ui.styleButton(back);
        back.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { finish(); }
        });
        root.addView(back, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl14, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
