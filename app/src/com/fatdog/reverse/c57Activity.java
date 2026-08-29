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
import android.widget.TextView;
import android.widget.Toast;

/**
 * KL20 破壁飞升：三代壳综合——三层保护叠加。
 * libk20.so 导出：nativeAntiDebug/nativeDecrypt/nativeSeed/nativeAnswer/nativeOllvm/nativeVmExecute/nativeStatus
 * 外层：XOR+Base64 加密；中层：OLLVM 混淆；内层：VMP 字节码。
 * 玩家需：① 绕过反调试 → ② 脱外层壳 → ③ 分析 OLLVM → ④ 逆向 VMP → ⑤ 算出答案。
 */
public class c57Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL20 · 破壁飞升（★★★★★ 收官卷）\n\n"
                + "libk20.so 导出七个函数：\n"
                + "  int    nativeAntiDebug()\n"
                + "  String nativeDecrypt()\n"
                + "  int    nativeSeed()\n"
                + "  String nativeAnswer()\n"
                + "  int    nativeOllvm(int seed)\n"
                + "  int    nativeVmExecute()\n"
                + "  String nativeStatus()\n\n"
                + "三层保护叠加：\n"
                + "  外层：XOR+Base64 加密\n"
                + "  中层：OLLVM 状态机混淆\n"
                + "  内层：VMP 字节码执行\n"
                + "额外：反调试 + CRC 自校验");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        // 答案输入框
        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入答案（32位 hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        int p = Ui.dp(10);
        ansIn.setPadding(p, p, p, p);
        root.addView(ansIn, Ui.fullWidth(10));

        // 提交按钮
        Button subBtn = new Button(this);
        subBtn.setText("提交答案"); Ui.styleButton(subBtn);
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(c57Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Hk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(c57Activity.this, "FLAG_18_KL20{all_shells_broken}");
                    PassLog.mark(c57Activity.this, "KL20");
                } else {
                    Toast.makeText(c57Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(c57Activity.this)
                        .setTitle("提示")
                        .setMessage("三代壳分析路线：\n\n"
                                + "① 检查反调试：ptrace + TracerPid，绕过后才能正常工作；\n"
                                + "② 外层：XOR+Base64 加密（同 KL16），解密得到 hex 数据；\n"
                                + "③ 中层：OLLVM 状态机（同 KL18），分析 case 路径还原逻辑；\n"
                                + "④ 内层：VMP 字节码（同 KL19），逐指令翻译还原算法。\n\n"
                                + "nativeDecrypt() → 外层解密\n"
                                + "nativeOllvm(seed) → 中层变换\n"
                                + "nativeVmExecute() → 内层执行\n"
                                + "三者叠加得到最终答案。\n\n"
                                + "注意诱饵 Fatdog_breaker（多 er），真标记 Fatdog_break。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        // banner
        root.addView(Ui.banner(this, R.drawable.level_kl20, 140));

        setContentView(root);
        ThemeKit.apply(this);
    }
}
