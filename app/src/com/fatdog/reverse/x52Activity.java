package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
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
 * KL15 万法归宗（★★★★★ 综合收官卷）。
 *
 * 三阶段递进谜题，四个独立 native 入口：
 *   computeA() → computeB(a) → computeC(a,b) → verify(a,b,c)
 * 三个值全部还原正确才能通过，UI 不自动填入、不打印中间值。
 */
public class x52Activity extends Activity {

    private EditText aBox, bBox, cBox;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL15 · 万法归宗（★★★★★）\n\n"
                + "三阶段递进谜题，每阶段算法不同：\n"
                + "A=XOR+移位，B=CRC衍生，C=SHA256组合。\n\n"
                + "按 computeA → computeB(a) → computeC(a,b) 还原，\n"
                + "三值全对 verify 才返回 1，本关不自动填答案。");
        tv.setGravity(Gravity.CENTER);
        tv.setTextColor(Color.WHITE);
        tv.setTextSize(15);
        root.addView(tv, Ui.wrap(6));

        int p = Ui.dp(10);

        aBox = new EditText(this);
        aBox.setHint("A 值（十进制整数）");
        aBox.setTextColor(Color.WHITE);
        aBox.setTypeface(Typeface.MONOSPACE);
        aBox.setBackgroundColor(0x33FFFFFF);
        aBox.setPadding(p, p, p, p);
        root.addView(aBox, Ui.fullWidth(10));

        bBox = new EditText(this);
        bBox.setHint("B 值（十进制整数）");
        bBox.setTextColor(Color.WHITE);
        bBox.setTypeface(Typeface.MONOSPACE);
        bBox.setBackgroundColor(0x33FFFFFF);
        bBox.setPadding(p, p, p, p);
        root.addView(bBox, Ui.fullWidth(10));

        cBox = new EditText(this);
        cBox.setHint("C 值（十进制整数）");
        cBox.setTextColor(Color.WHITE);
        cBox.setTypeface(Typeface.MONOSPACE);
        cBox.setBackgroundColor(0x33FFFFFF);
        cBox.setPadding(p, p, p, p);
        root.addView(cBox, Ui.fullWidth(10));

        Button submit = new Button(this);
        submit.setText("验证三值 verify(A, B, C)");
        Ui.styleButton(submit);
        submit.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String sa = aBox.getText().toString().trim();
                String sb = bBox.getText().toString().trim();
                String sc = cBox.getText().toString().trim();
                if (sa.isEmpty() || sb.isEmpty() || sc.isEmpty()) {
                    Toast.makeText(x52Activity.this, "请填入 A、B、C 三值", Toast.LENGTH_SHORT).show();
                    return;
                }
                int a, b, c;
                try {
                    a = Integer.parseInt(sa);
                    b = Integer.parseInt(sb);
                    c = Integer.parseInt(sc);
                } catch (NumberFormatException e) {
                    Toast.makeText(x52Activity.this, "请输入十进制整数", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (Am.nativeVerify(a, b, c) == 1) {
                    Celebration.show(x52Activity.this, "FLAG_18_KL15{all_methods_converge}");
                    PassLog.mark(x52Activity.this, "KL15");
                } else {
                    Toast.makeText(x52Activity.this, "验证失败，三值至少一个不对。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(submit, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(x52Activity.this)
                        .setTitle("提示")
                        .setMessage("四个独立入口：computeA → computeB(a) → computeC(a,b) → verify(a,b,c)。\n"
                                + "正解方向：IDA/Ghidra 还原每一阶段算法，按依赖顺序算出 A、B、C；也可 Frida hook 三个 compute 出口观察返回值对拍。\n"
                                + "三值全对 verify 才返回 1。")
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

        root.addView(Ui.banner(this, R.drawable.level_kl15, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
