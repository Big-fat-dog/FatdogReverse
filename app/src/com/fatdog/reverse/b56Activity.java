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

// 太玄之初 KL19 · 虚空造化：VMP 虚拟机保护。
// libk19.so 导出：nativeDecrypt/nativeSeed/nativeAnswer/nativeVmExecute/nativeDirect
// 核心算法被编译为自定义 VM 字节码（寄存器式 8 寄存器 + 25 条指令）。
// 玩家需：① 逆向 VM 解释器 → ② 提取解密字节码 → ③ 逐指令翻译 → ④ 算出答案。
public class b56Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL19 · 虚空造化（★★★★）\n\n"
                + "libk19.so 导出五个函数：\n"
                + "  String nativeDecrypt()\n"
                + "  int    nativeSeed()\n"
                + "  String nativeAnswer()\n"
                + "  int    nativeVmExecute()\n"
                + "  int    nativeDirect(int seed)\n\n"
                + "VMP 虚拟机保护：寄存器式 8 寄存器\n"
                + "25 条指令，字节码轮转 XOR 加密。");
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
                if (ans.isEmpty()) { Toast.makeText(b56Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Gk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(b56Activity.this, "FLAG_18_KL19{vm_cracked}");
                    PassLog.mark(b56Activity.this, "KL19");
                } else {
                    Toast.makeText(b56Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(b56Activity.this)
                        .setTitle("提示")
                        .setMessage("VMP 分析路线：\n\n"
                                + "① IDA 找 JNI 函数 → 顺藤摸到 VM 解释器（大 switch-case）；\n"
                                + "② 逆向每个 case 的指令语义——25 条指令对应 25 个 case；\n"
                                + "③ 提取加密字节码 → 分析 XOR 轮转规律（8 字节循环密钥）；\n"
                                + "④ 解密字节码 → 逐条翻译为 C 代码 → 复刻算法。\n\n"
                                + "nativeVmExecute() 走 VM，nativeDirect(seed) 直接算。\n"
                                + "两者输入相同种子应返回相同值，可对拍验证。\n"
                                + "注意诱饵 Fatdog_reverser（多 er），真标记 Fatdog_reverse。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        // banner
        root.addView(Ui.banner(this, R.drawable.level_kl19, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
