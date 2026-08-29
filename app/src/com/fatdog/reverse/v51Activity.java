package com.fatdog.reverse;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
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
 * 三步提交：①partA → ②partB → ③combine
 * 或一键取答案（nativeCombineFromC）。
 */
public class v51Activity extends Activity {

    private TextView log;
    private EditText ansBox;
    private int valA, valB;

    private void append(String s) {
        log.append(s);
    }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(Ui.dp(22), Ui.dp(18), Ui.dp(22), Ui.dp(12));

        root.addView(Ui.banner(this, R.drawable.level_kl14, 140));

        TextView hi = new TextView(this);
        hi.setText("KL14 · 偷天换日（★★★★）");
        hi.setTextSize(18); hi.setTextColor(Color.WHITE);
        hi.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        root.addView(hi);

        TextView desc = new TextView(this);
        desc.setText("三 so 交叉验证：libm13a 算 digest_A，libm13b 算 digest_B，libm13c 拼装 A‖B 再 hash 得最终答案。patch 任一 so 即全链失效。");
        desc.setTextSize(13); desc.setTextColor(0xCCFFFFFF);
        desc.setPadding(0, Ui.dp(6), 0, Ui.dp(10));
        root.addView(desc);

        ScrollView sv = new ScrollView(this);
        log = new TextView(this);
        log.setTypeface(android.graphics.Typeface.MONOSPACE);
        log.setTextSize(12); log.setTextColor(Color.WHITE);
        log.setMovementMethod(new ScrollingMovementMethod());
        sv.addView(log);
        LinearLayout.LayoutParams svLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        root.addView(sv, svLp);

        /* 三步操作 */
        Button btnA = new Button(this);
        btnA.setText("① 取 PartA"); Ui.styleButton(btnA);
        btnA.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                valA = Zn.nativePartA();
                append("[A] nativePartA → " + valA);
            }
        });
        root.addView(btnA);

        Button btnB = new Button(this);
        btnB.setText("② 取 PartB"); Ui.styleButton(btnB);
        btnB.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                valB = Zn.nativePartBFromB();
                append("[B] nativePartBFromB → " + valB);
            }
        });
        root.addView(btnB);

        Button btnC = new Button(this);
        btnC.setText("③ Combine（Java 传值）"); Ui.styleButton(btnC);
        btnC.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String r = Zn.nativeCombine(valA, valB);
                append("[C] nativeCombine → " + r);
            }
        });
        root.addView(btnC);

        /* 一键取答案 */
        Button btnOne = new Button(this);
        btnOne.setText("一键取答案（C 内部交叉调用）"); Ui.styleButton(btnOne);
        btnOne.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String r = Zn.nativeCombineFromC();
                append("[One] nativeCombineFromC → " + r);
                ansBox.setText(r);
            }
        });
        root.addView(btnOne);

        /* 提交 */
        ansBox = new EditText(this);
        ansBox.setHint("输入答案（32位 hex）");
        ansBox.setTextColor(Color.WHITE);
        ansBox.setTypeface(android.graphics.Typeface.MONOSPACE);
        ansBox.setBackgroundColor(0x33FFFFFF);
        int p = Ui.dp(10);
        ansBox.setPadding(p, p, p, p);
        root.addView(ansBox);

        Button submit = new Button(this);
        submit.setText("提交"); Ui.styleButton(submit);
        submit.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansBox.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(v51Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                /* 本地比对：重新算一遍 nativeCombineFromC，与用户提交值比较 */
                String expected = Zn.nativeCombineFromC();
                if (ans.equals(expected)) {
                    append("\n✔ 通过！");
                    Celebration.show(v51Activity.this, "FLAG_18_KL14{mesh_of_three}");
                    PassLog.mark(v51Activity.this, "KL14");
                } else {
                    append("\n✘ 答案不匹配（期望：" + expected + "）");
                    Toast.makeText(v51Activity.this, "答案不对", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(submit);

        /* 返回 */
        Button back = new Button(this);
        back.setText("返回"); Ui.styleButton(back);
        back.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { finish(); }
        });
        root.addView(back);

        setContentView(root);
    }
}
