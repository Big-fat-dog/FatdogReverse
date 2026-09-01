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

// 幽冥海 KL13 · 声东击西：反 patch 对抗——CRC 自校验。
// libm12.so 的 guard() 内嵌 CRC 校验：每次调用 check() 时重新算 CRC 比对。
// patch 任何指令都会改变 CRC → 校验失败 → 静默返回 0。
// 解法：① Frida hook check 强制返回 1（跳过 CRC）；
//       ② patch CRC 基线值（找到常量改为 patched 代码的 CRC）；
//       ③ 完整复刻算法 → Python 本地计算。
public class u50Activity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("幽冥海 KL13 · 声东击西\n\n"
                + "libm12.so 内嵌 CRC 自校验——\n"
                + "guard() 每次调用都会重新校验代码完整性。\n"
                + "patch 任何指令都会改变 CRC → 校验失败 → 返回 0。\n\n"
                + "三解全开：\n"
                + "① Frida hook check 强制返回 1（跳过 CRC）\n"
                + "② 找到 CRC 基线常量改为 patched 代码的 CRC\n"
                + "③ 完整复刻算法 → Python 本地计算");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        // check 状态显示
        final TextView checkStatus = new TextView(this);
        int g = Ap.nativeCheck();
        checkStatus.setText("check() = " + g + (g == 1 ? "（guard 已通过 ✓）" : "（guard 未通过 / 未 patch）"));
        checkStatus.setGravity(Gravity.CENTER);
        checkStatus.setTextColor(g == 1 ? 0xFF67C23A : 0xFFFB7299);
        box.addView(checkStatus, Ui.wrap(6));

        // 答案输入框
        final EditText ansIn = new EditText(this);
        ansIn.setHint("提交 guard(MAGIC) 的返回值（十进制）");
        ansIn.setLayoutParams(Ui.fullWidth(14));
        ansIn.setEnabled(g == 1);

        // 重新检测按钮
        Button recheck = new Button(this);
        recheck.setText("重新检测 check");
        Ui.styleButton(recheck);
        recheck.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int g = Ap.nativeCheck();
                checkStatus.setText("check() = " + g + (g == 1 ? "（guard 已通过 ✓）" : "（guard 未通过 / 未 patch）"));
                checkStatus.setTextColor(g == 1 ? 0xFF67C23A : 0xFFFB7299);
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
                int g = Ap.nativeCheck();
                if (g != 1) {
                    Toast.makeText(u50Activity.this,
                            "check 未通过，请先绕过 CRC 校验。", Toast.LENGTH_SHORT).show();
                    return;
                }
                String ans = ansIn.getText().toString().trim();
                // guard(MAGIC) 应返回 1（CRC 通过 + MAGIC 匹配）
                int expected = Ap.nativeGuard(0xCAFEBABE);
                if (ans.equals(String.valueOf(expected))) {
                    Celebration.show(u50Activity.this, "FLAG_18_KL13{crc_cannot_protect}");
                    PassLog.mark(u50Activity.this, "KL13");
                } else {
                    Toast.makeText(u50Activity.this,
                            "答案不对，guard(MAGIC) 返回什么？", Toast.LENGTH_SHORT).show();
                }
            }
        });

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(u50Activity.this)
                        .setTitle("提示")
                        .setMessage("Frida 跳过 CRC 最简单：\n"
                                + "Java.perform(function(){\n"
                                + "  var chk = Module.findExportByName('libm12.so','check');\n"
                                + "  Interceptor.attach(chk, {\n"
                                + "    onLeave: function(r){ r.replace(ptr(1)); }\n"
                                + "  });\n"
                                + "});\n\n"
                                + "hook 后 check() 恒返回 1，guard(MAGIC) 也自然通过。\n"
                                + "答案 = guard(0xCAFEBABE) 的十进制返回值。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kl13, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }
}
