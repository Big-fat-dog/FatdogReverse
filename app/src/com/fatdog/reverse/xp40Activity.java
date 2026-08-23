package com.fatdog.reverse;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

public class xp40Activity extends Activity {
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
        tv.setText("Xposed 第三关 · 探囊取物\n\n密码藏在 SecretVault 类的私有静态字段 s_hiddenKey 中。\n用 XposedHelpers.getStaticObjectField 读取它，然后通过 Toast 打印出来。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));
        status = new TextView(this);
        status.setText("等待玩家操作…");
        status.setTextSize(14); status.setGravity(Gravity.CENTER);
        status.setPadding(0, Ui.dp(16), 0, Ui.dp(16));
        box.addView(status, Ui.wrap(4));
        setContentView(box); ThemeKit.apply(this);
        // 触发一次字段访问让 Xposed 模块有机会 Hook
        String v = SecretVault.getKey();
    }
}
