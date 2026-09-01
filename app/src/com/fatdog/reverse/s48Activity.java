package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

// 幽冥海 KL11 · 偷梁换柱：SO patch 入门——nop 掉 guard 里的比较指令。
// libm10.so 导出 guard(input) 和 answer()：
//   guard(0) 默认返回 0（未 patch）；patch 后恒返回 1。
//   answer() 返回 MAGIC ^ XOR_KEY（十进制）。
// 玩家需要：① IDA 定位 guard 函数；② nop 掉 CMP+BEQ；③ 重打包；④ 调用 answer() 拿答案。
public class s48Activity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("幽冥海 KL11 · 偷梁换柱\n\n"
                + "libm10.so 导出两个函数：\n"
                + "  int guard(int input)\n"
                + "  int answer()\n\n"
                + "guard(0) 当前返回 0——你需要 patch so 让它返回 1。\n"
                + "IDA 找到 guard 函数，nop 掉比较跳转指令，重打包安装。\n"
                + "guard 通过后，answer() 会告诉你最终答案。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        // guard 状态显示
        final TextView guardStatus = new TextView(this);
        int g = Tu.nativeGuard(0);
        guardStatus.setText("guard(0) = " + g + (g == 1 ? "（已 patch ✓）" : "（未 patch）"));
        guardStatus.setGravity(Gravity.CENTER);
        guardStatus.setTextColor(g == 1 ? 0xFF67C23A : 0xFFFB7299);
        box.addView(guardStatus, Ui.wrap(6));

        // 答案输入框（guard 通过后可用）
        final EditText ansIn = new EditText(this);
        ansIn.setHint("提交 answer() 的返回值（十进制）");
        ansIn.setLayoutParams(Ui.fullWidth(14));
        ansIn.setEnabled(g == 1);

        // 重新检测按钮
        Button recheck = new Button(this);
        recheck.setText("重新检测 guard");
        Ui.styleButton(recheck);
        recheck.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int g = Tu.nativeGuard(0);
                guardStatus.setText("guard(0) = " + g + (g == 1 ? "（已 patch ✓）" : "（未 patch）"));
                guardStatus.setTextColor(g == 1 ? 0xFF67C23A : 0xFFFB7299);
                ansIn.setEnabled(g == 1);
            }
        });
        box.addView(recheck, Ui.wrap(10));

        box.addView(ansIn);

        Button subBtn = new Button(this);
        subBtn.setText("提交答案");
        Ui.styleButton(subBtn);
        box.addView(subBtn, Ui.wrap(12));

        // 提交逻辑
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int g = Tu.nativeGuard(0);
                if (g != 1) {
                    Toast.makeText(s48Activity.this,
                            "guard 未通过，请先 patch so。", Toast.LENGTH_SHORT).show();
                    return;
                }
                String ans = ansIn.getText().toString().trim();
                int expected = Tu.nativeAnswer();
                if (ans.equals(String.valueOf(expected))) {
                    Celebration.show(s48Activity.this, "FLAG_18_KL11{nop_the_guard}");
                    PassLog.mark(s48Activity.this, "KL11");
                } else {
                    Toast.makeText(s48Activity.this,
                            "答案不对，再看看 answer() 返回什么。", Toast.LENGTH_SHORT).show();
                }
            }
        });

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(s48Activity.this)
                        .setTitle("提示")
                        .setMessage("patch 入门三步：\n"
                                + "① IDA/Ghidra 打开 libm10.so，搜索导出符号 guard；\n"
                                + "② 找到 CMP W0, #0x46415444 和 B.EQ 跳转指令；\n"
                                + "③ 将 B.EQ 改为 NOP（ARM64: 0x1F2003D5），重打包。\n\n"
                                + "Frida 也能过（hook guard 强制返回 1），但本关教的是静态 patch。\n"
                                + "答案 = answer() 的十进制返回值。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        // banner
        box.addView(Ui.banner(this, R.drawable.level_kl11, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }
}
