package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class xp42Activity extends Activity {
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
        tv.setText("Xposed 最终关 · 万剑归宗\n\n本关验证持久化 Hook：点击下方按钮杀掉本应用进程，\n然后从桌面重新打开。\n如果 Hook 在冷启动后仍然生效（只有 Xposed 能做到），即自动通关。\n\n这就是 Frida 做不到的事。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        Button kill = new Button(this);
        kill.setText("自毁进程（测试持久化）");
        kill.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Kl42Gate.tick(xp42Activity.this);   // 落盘记一次（跨进程存活）
                android.os.Process.killProcess(android.os.Process.myPid());
            }
        });
        box.addView(kill, Ui.wrap(12));

        status = new TextView(this);
        status.setText("等待验证…");
        status.setTextSize(14); status.setGravity(Gravity.CENTER);
        status.setPadding(0, Ui.dp(12), 0, Ui.dp(12));
        box.addView(status, Ui.wrap(4));

        box.addView(Ui.banner(this, R.drawable.level_42, 140));

        setContentView(Ui.wrapScroll(box)); ThemeKit.apply(this);

        // 冷启动检测：coldStartCheck 被模块 Hook 成 true（持久化生效）
        // 且 ticks>0（自毁前落盘的计数，重开后仍可读到）→ 通关
        if (Kl42Gate.coldStartCheck() && Kl42Gate.getTicks(this) > 0) {
            passed = true;
            status.setText("✓ 持久化 Hook 生效！欢迎登顶。");
            Celebration.show(xp42Activity.this, "FLAG_18_L42{persistence_is_power}");
            PassLog.mark(xp42Activity.this, "L42");
        } else if (Kl42Gate.coldStartCheck()) {
            status.setText("Hook 已生效，但还没经过自毁重启的考验。\n点「自毁进程」，再从桌面重开本页。");
        } else {
            status.setText("未检测到持久化 Hook。\n请先挂载模块并重启手机，再回来点「自毁进程」测试。");
        }
    }
}
