package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
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
                Kl42Gate.tick();
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

        setContentView(box); ThemeKit.apply(this);

        // 冷启动检测：如果 Xposed Hook 仍生效则通关
        if (Kl42Gate.coldStartCheck() && Kl42Gate.getTicks() > 0) {
            passed = true;
            status.setText("✓ 持久化 Hook 生效！欢迎登顶。");
            Celebration.show(xp42Activity.this, "FLAG_18_L42{persistence_is_power}");
            PassLog.mark(xp42Activity.this, "L42");
        } else if (Kl42Gate.coldStartCheck()) {
            status.setText("Hook 检测通过但未经过自毁测试。\n点击自毁按钮杀掉进程，再从桌面重开来验证。");
        }
    }
}
