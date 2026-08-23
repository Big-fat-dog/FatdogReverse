package com.fatdog.reverse;


import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

// L38 初探模块：XpGate.check() 默认返回 false。
// 玩家写 Xposed 模块 Hook 此方法强制返回 true，打开本页即自动通关。
// 教学目标：掌握 findAndHookMethod + afterHookedMethod + setResult 基础用法。
public class xp38Activity extends Activity {

    private TextView status;
    private boolean passed = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("Xposed 第一关 · 初探模块\n\n"
                + "本页有一个方法 XpGate.check()，默认返回 false。\n"
                + "请编写一个 LSPosed 模块，用 findAndHookMethod 把它改成返回 true。\n"
                + "模块安装并激活后，重新打开本页面即自动通关。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        status = new TextView(this);
        status.setText("检测中…");
        status.setTextSize(16);
        status.setGravity(Gravity.CENTER);
        status.setPadding(0, Ui.dp(20), 0, Ui.dp(20));
        box.addView(status, Ui.wrap(4));

        setContentView(box);
        ThemeKit.apply(this);
    }

    @Override
    protected void onResume() {
        super.onResume();
        boolean hooked = XpGate.check();
        if (hooked && !passed) {
            passed = true;
            status.setText("✓ 检测到 Hook 生效！");
            Celebration.show(xp38Activity.this, "FLAG_18_L38{puppet_line_attached}");
            PassLog.mark(xp38Activity.this, "L38");
        } else if (!hooked) {
            status.setText("check() 返回 false —— 模块尚未生效。\n请确认 LSPosed 已激活且作用域包含本应用，然后重启靶场。");
        }
    }
}
