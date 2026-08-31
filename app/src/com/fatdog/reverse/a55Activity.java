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

// 太玄之初 KL18 · 乾坤迷阵：OLLVM 控制流平坦化。
// libk18.so 导出：nativeDecrypt/nativeSeed/nativeAnswer/nativeOllvm/nativeCore
// 状态机 16 case（12 真实 + 4 虚假），指令替换 + 字符串加密。
// 玩家需：① 识别状态机结构 → ② 标记真实/虚假 case → ③ 还原算法 → ④ 算出答案。
public class a55Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL18 · 乾坤迷阵（★★★）\n\n"
                + "libk18.so 导出五个函数：\n"
                + "  String nativeDecrypt()\n"
                + "  int    nativeSeed()\n"
                + "  String nativeAnswer()\n"
                + "  int    nativeOllvm(int seed)\n"
                + "  int    nativeCore(int seed)\n\n"
                + "OLLVM 控制流平坦化：16 个 case 的状态机\n"
                + "（12 真实 + 4 虚假），指令替换 + 字符串加密。");
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
                if (ans.isEmpty()) { Toast.makeText(a55Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Fk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(a55Activity.this, "FLAG_18_KL18{ollvm_deflattened}");
                    PassLog.mark(a55Activity.this, "KL18");
                } else {
                    Toast.makeText(a55Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(a55Activity.this)
                        .setTitle("提示")
                        .setMessage("OLLVM 分析路线：\n\n"
                                + "① IDA 加载 libk18.so → 找 JNI 函数 → 顺藤摸到状态机；\n"
                                + "② switch dispatcher 里 16 个 case，标记真实/虚假路径；\n"
                                + "③ 虚假路径特征：提前 return 0、跳到死循环、无意义运算；\n"
                                + "④ 真实路径：XOR → ROL → OLLVM_ADD → XOR → 比较。\n\n"
                                + "指令替换：a+b = (a^b)+((a&b)<<1)，是 OLLVM 标准手法。\n"
                                + "nativeOllvm(seed) 暴露状态机，nativeCore(seed) 暴露原始算法，可对拍。\n"
                                + "注意诱饵 Fatdog_folder（多 er），真标记 Fatdog_unfold。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        // banner
        root.addView(Ui.banner(this, R.drawable.level_kl18, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
