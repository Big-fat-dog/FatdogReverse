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

// 太玄之初 KL16 · 破壳新生：一代壳 DEX 静态加密——XOR+旋转解密还原。
// libk16.so 导出三个函数：
//   String nativeDecrypt()  → 解密后 DEX 的 hex
//   int    nativeSeed()     → 提取的种子值
//   String nativeAnswer()   → SHA-256(seed) 最终答案
// 玩家需要：① 分析 so 还原解密算法；② 提取种子；③ 算出答案提交。
public class y53Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL16 · 破壳新生（★）\n\n"
                + "libk16.so 导出三个函数：\n"
                + "  String nativeDecrypt()\n"
                + "  int    nativeSeed()\n"
                + "  String nativeAnswer()\n\n"
                + "追踪 Application 入口 → 找解密函数 → 还原算法 → 算出答案。");
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
                if (ans.isEmpty()) { Toast.makeText(y53Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Dk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(y53Activity.this, "FLAG_18_KL16{shell_broken}");
                    PassLog.mark(y53Activity.this, "KL16");
                } else {
                    Toast.makeText(y53Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(y53Activity.this)
                        .setTitle("提示")
                        .setMessage("一代壳分析路线：\n\n"
                                + "① jadx 找壳的 Application → attachBaseContext 调 native 解密；\n"
                                + "② IDA 分析 libk16.so → 找 XOR_KEY（.rodata 段全局数组）；\n"
                                + "③ Python 复刻三轮解密：XOR → 循环左移3位 → 组内 XOR 累积。\n\n"
                                + "Frida 路线：直接调 Dk.nativeAnswer() 拿答案。\n"
                                + "注意诱饵 Fatdog_packer（多 er），真标记 Fatdog_pack。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        // banner
        root.addView(Ui.banner(this, R.drawable.level_kl16, 140));

        setContentView(root);
        ThemeKit.apply(this);
    }
}
