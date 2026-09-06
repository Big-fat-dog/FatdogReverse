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

// 太玄之初 KKL1 · 玄冥渊：C++ vtable 派发 + 抽取回填（教学版）。
// libkkl1.so 导出三个函数（JNI 桥 Kkl1Native）：
//   String nativeDecrypt()  → 抽取回填并解密后的明文 hex
//   int    nativeSeed()     → 提取的种子值
//   String nativeAnswer()   → SHA-256(seed) 最终答案
// 玩家需要：① 认 vtable 结构（三个派生类只有 RealCipher 是真身）
//           ② 还原抽取表与解密链 → ③ 算出种子 → ④ 提交 SHA-256(seed)。
public class kkl1Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KKL1 · 玄冥渊（★☆）\n\n"
                + "libkkl1.so 导出三个函数：\n"
                + "  String nativeDecrypt()\n"
                + "  int    nativeSeed()\n"
                + "  String nativeAnswer()\n\n"
                + "数据先按抽取表从 POOL 回填成密文，再 XOR+循环移位解密。\n"
                + "抽取表藏在 C++ 虚函数表里——三张表只有一张是真的。");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        // 答案输入框
        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入答案（64位 hex）");
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
                if (ans.isEmpty()) { Toast.makeText(kkl1Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Kkl1Native.nativeAnswer();
                if (ans.equalsIgnoreCase(expected)) {
                    Celebration.show(kkl1Activity.this, "FLAG_18_KKL1{abyss_of_mystery}");
                    PassLog.mark(kkl1Activity.this, "KKL1");
                } else {
                    Toast.makeText(kkl1Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(kkl1Activity.this)
                        .setTitle("提示")
                        .setMessage("玄冥渊分析路线：\n\n"
                                + "① jadx：Kkl1Native 是 JNI 桥，nativeDecrypt/nativeSeed/nativeAnswer 全部在 libkkl1.so；\n"
                                + "② IDA：找 CipherBase 的三个派生类（DecoyA/DecoyB/RealCipher），\n"
                                + "    vtable 间接调用 table() 取抽取表——只有 RealCipher 返回真表；\n"
                                + "③ 复刻：按真表从 POOL 回填 8 组（每组 4 字节）→ XOR_KEY 逐字节异或\n"
                                + "    → 循环左移 3 位 → 明文第 10 字节起 8 位十进制即种子；\n"
                                + "④ 答案：SHA-256(种子 4 字节大端) 的 hex。\n\n"
                                + "Frida 路线：直接调 Kkl1Native.nativeAnswer() 拿答案。\n"
                                + "注意诱饵 Fatdog_hollow（一字之差），真标记 Fatdog_hallow。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));
        root.addView(Ui.banner(this, R.drawable.level_kkl1, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
