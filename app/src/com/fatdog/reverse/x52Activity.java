package com.fatdog.reverse;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
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
 * 与前几关不同：三阶段递进谜题，不是简单的 guard→answer。
 *   阶段 A：computeA → 种子值
 *   阶段 B：computeB(a) → 基于 A 的衍生值
 *   阶段 C：computeC(a,b) → 组合 A+B 的最终值
 *   验证：verify(a,b,c) → 三值全对才解锁
 */
public class x52Activity extends Activity {

    private TextView log;
    private EditText aBox, bBox, cBox;
    private int valA, valB, valC;

    private void append(String s) { log.append(s + "\n"); }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(Ui.dp(22), Ui.dp(18), Ui.dp(22), Ui.dp(12));

        root.addView(Ui.banner(this, R.drawable.level_kl15, 140));

        TextView hi = new TextView(this);
        hi.setText("KL15 · 万法归宗（★★★★★）");
        hi.setTextSize(18); hi.setTextColor(Color.WHITE);
        hi.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(hi);

        TextView desc = new TextView(this);
        desc.setText("收官综合卷：三阶段递进谜题，每阶段算法不同。"
                + "A=XOR+移位，B=CRC衍生，C=SHA256组合。三值全对才解锁。");
        desc.setTextSize(13); desc.setTextColor(0xCCFFFFFF);
        desc.setPadding(0, Ui.dp(6), 0, Ui.dp(8));
        root.addView(desc);

        ScrollView sv = new ScrollView(this);
        log = new TextView(this);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextSize(12); log.setTextColor(Color.WHITE);
        log.setMovementMethod(new ScrollingMovementMethod());
        sv.addView(log);
        root.addView(sv, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        /* ── 阶段 A ── */
        Button btnA = new Button(this);
        btnA.setText("阶段 A · computeA()"); Ui.styleButton(btnA);
        btnA.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                valA = Am.nativeComputeA();
                append("[A] computeA() → " + valA + "  (0x" + Integer.toHexString(valA) + ")");
                aBox.setText(String.valueOf(valA));
            }
        });
        root.addView(btnA);

        /* ── 阶段 B ── */
        Button btnB = new Button(this);
        btnB.setText("阶段 B · computeB(A)"); Ui.styleButton(btnB);
        btnB.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (valA == 0 && aBox.getText().toString().isEmpty()) {
                    Toast.makeText(x52Activity.this, "请先完成阶段 A", Toast.LENGTH_SHORT).show();
                    return;
                }
                /* 如果用户手动改了 A 的值，用输入框的 */
                String aStr = aBox.getText().toString().trim();
                if (!aStr.isEmpty()) valA = Integer.parseInt(aStr);
                valB = Am.nativeComputeB(valA);
                append("[B] computeB(" + valA + ") → " + valB + "  (0x" + Integer.toHexString(valB) + ")");
                bBox.setText(String.valueOf(valB));
            }
        });
        root.addView(btnB);

        /* ── 阶段 C ── */
        Button btnC = new Button(this);
        btnC.setText("阶段 C · computeC(A, B)"); Ui.styleButton(btnC);
        btnC.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String aStr = aBox.getText().toString().trim();
                String bStr = bBox.getText().toString().trim();
                if (aStr.isEmpty() || bStr.isEmpty()) {
                    Toast.makeText(x52Activity.this, "请先完成 A 和 B", Toast.LENGTH_SHORT).show();
                    return;
                }
                valA = Integer.parseInt(aStr);
                valB = Integer.parseInt(bStr);
                valC = Am.nativeComputeC(valA, valB);
                append("[C] computeC(" + valA + ", " + valB + ") → " + valC + "  (0x" + Integer.toHexString(valC) + ")");
                cBox.setText(String.valueOf(valC));
            }
        });
        root.addView(btnC);

        /* ── 输入区 ── */
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        int p = Ui.dp(6);

        aBox = new EditText(this); aBox.setHint("A"); aBox.setTextSize(12);
        aBox.setTextColor(Color.WHITE); aBox.setTypeface(Typeface.MONOSPACE);
        aBox.setBackgroundColor(0x33FFFFFF); aBox.setPadding(p, p, p, p);
        row.addView(aBox, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        bBox = new EditText(this); bBox.setHint("B"); bBox.setTextSize(12);
        bBox.setTextColor(Color.WHITE); bBox.setTypeface(Typeface.MONOSPACE);
        bBox.setBackgroundColor(0x33FFFFFF); bBox.setPadding(p, p, p, p);
        row.addView(bBox, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        cBox = new EditText(this); cBox.setHint("C"); cBox.setTextSize(12);
        cBox.setTextColor(Color.WHITE); cBox.setTypeface(Typeface.MONOSPACE);
        cBox.setBackgroundColor(0x33FFFFFF); cBox.setPadding(p, p, p, p);
        row.addView(cBox, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        root.addView(row);

        /* ── 提交 ── */
        Button submit = new Button(this);
        submit.setText("验证三值 verify(A, B, C)"); Ui.styleButton(submit);
        submit.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String sa = aBox.getText().toString().trim();
                String sb = bBox.getText().toString().trim();
                String sc = cBox.getText().toString().trim();
                if (sa.isEmpty() || sb.isEmpty() || sc.isEmpty()) {
                    Toast.makeText(x52Activity.this, "请填入 A、B、C 三值", Toast.LENGTH_SHORT).show();
                    return;
                }
                int a = Integer.parseInt(sa);
                int b = Integer.parseInt(sb);
                int c = Integer.parseInt(sc);
                int r = Am.nativeVerify(a, b, c);
                append("[verify] verify(" + a + ", " + b + ", " + c + ") → " + r);
                if (r == 1) {
                    append("\n✔ 三值全部匹配！");
                    Celebration.show(x52Activity.this, "FLAG_18_KL15{all_methods_converge}");
                    PassLog.mark(x52Activity.this, "KL15");
                } else {
                    append("\n✘ 至少一个值不对");
                    Toast.makeText(x52Activity.this, "验证失败", Toast.LENGTH_SHORT).show();
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
