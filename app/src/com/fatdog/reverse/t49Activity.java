package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

// 幽冥海 KL12 · 移花接木：动态 patch（Frida hook）入门。
// libm11.so 导出 seal() 和 check(val)：
//   seal() 返回内嵌常量 0x1337CAFE；
//   check(val) 校验 val == 0x1337CAFE 才返回 1。
// 本关教 Frida：hook seal 强制返回正确值，check 自然通过。
// 静态 patch 也能过（改多处），但 Frida 一行搞定。
public class t49Activity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("幽冥海 KL12 · 移花接木\n\n"
                + "libm11.so 导出两个函数：\n"
                + "  int seal()      — 返回内嵌常量\n"
                + "  int check(val)  — 校验 val == 内嵌常量\n\n"
                + "seal() 里藏着一把钥匙——找到它，hook 它。\n"
                + "Frida 一行：hook seal 强制返回正确值，check 自然通过。\n"
                + "静态 patch 也能过，但需要改多处——这就是动态 patch 的优势。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        // check 状态显示
        final TextView checkStatus = new TextView(this);
        int s = Uk.nativeSeal();
        int g = Uk.nativeCheck(s);
        checkStatus.setText("check(seal()) = " + g + (g == 1 ? "（已 hook ✓）" : "（未 hook）"));
        checkStatus.setGravity(Gravity.CENTER);
        checkStatus.setTextColor(g == 1 ? 0xFF67C23A : 0xFFFB7299);
        box.addView(checkStatus, Ui.wrap(6));

        // 重新检测按钮
        Button recheck = new Button(this);
        recheck.setText("重新检测 check");
        Ui.styleButton(recheck);
        recheck.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int s = Uk.nativeSeal();
                int g = Uk.nativeCheck(s);
                checkStatus.setText("check(seal()) = " + g + (g == 1 ? "（已 hook ✓）" : "（未 hook）"));
                checkStatus.setTextColor(g == 1 ? 0xFF67C23A : 0xFFFB7299);
            }
        });
        box.addView(recheck, Ui.wrap(10));

        // 答案输入框
        final EditText ansIn = new EditText(this);
        ansIn.setHint("提交 seal() 的返回值（十六进制，如 0x1337cafe）");
        ansIn.setLayoutParams(Ui.fullWidth(14));
        ansIn.setEnabled(false);
        box.addView(ansIn);

        Button subBtn = new Button(this);
        subBtn.setText("提交答案");
        Ui.styleButton(subBtn);
        box.addView(subBtn, Ui.wrap(12));

        // 提交逻辑
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int s = Uk.nativeSeal();
                int g = Uk.nativeCheck(s);
                if (g != 1) {
                    Toast.makeText(t49Activity.this,
                            "check 未通过，请先 hook seal()。", Toast.LENGTH_SHORT).show();
                    return;
                }
                String ans = ansIn.getText().toString().trim().toLowerCase();
                // 接受多种格式：0x1337cafe / 1337cafe / 322372350
                int expected = Uk.nativeSeal();
                boolean ok = false;
                if (ans.equals(String.format("0x%x", expected))) ok = true;
                if (ans.equals(String.format("%x", expected))) ok = true;
                if (ans.equals(String.valueOf(expected))) ok = true;
                if (ok) {
                    Celebration.show(t49Activity.this, "FLAG_18_KL12{hook_the_seal}");
                    PassLog.mark(t49Activity.this, "KL12");
                } else {
                    Toast.makeText(t49Activity.this,
                            "答案不对，seal() 返回什么？", Toast.LENGTH_SHORT).show();
                }
            }
        });

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(t49Activity.this)
                        .setTitle("提示")
                        .setMessage("Frida 动态 patch 三行搞定：\n"
                                + "Java.perform(function(){\n"
                                + "  var seal = Module.findExportByName('libm11.so','seal');\n"
                                + "  Interceptor.attach(seal, {\n"
                                + "    onLeave: function(r){ r.replace(ptr(0x1337CAFE)); }\n"
                                + "  });\n"
                                + "});\n\n"
                                + "hook 后 check(seal()) 自然返回 1。\n"
                                + "答案 = seal() 的返回值（十六进制）。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kl12, 140));

        setContentView(box);
        ThemeKit.apply(this);
    }
}
