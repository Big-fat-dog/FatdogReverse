package com.fatdog.reverse;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

// L40 探囊取物：模块读出 SecretVault.s_hiddenKey 后调用 reportStolenKey 回传即自动通关。
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
        tv.setText("Xposed 第三关 · 探囊取物\n\n"
                + "密码藏在 SecretVault 类的私有静态字段 s_hiddenKey 中。\n"
                + "用 XposedHelpers.getStaticObjectField 读取它，\n"
                + "再调用 SecretVault.reportStolenKey(密码) 回传验证，\n"
                + "哈希对上即自动通关。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));
        status = new TextView(this);
        status.setText("等待模块回传…");
        status.setTextSize(14); status.setGravity(Gravity.CENTER);
        status.setPadding(0, Ui.dp(16), 0, Ui.dp(16));
        box.addView(status, Ui.wrap(4));
        box.addView(Ui.banner(this, R.drawable.level_40, 140));

        setContentView(box); ThemeKit.apply(this);
        // 触发一次字段访问让 Xposed 模块有机会 Hook
        String v = SecretVault.getKey();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (SecretVault.stolen && !passed) {
            passed = true;
            status.setText("✓ 私钥已得手！探囊取物，摘星拿月。");
            Celebration.show(xp40Activity.this, "FLAG_18_L40{secret_field_exposed}");
            PassLog.mark(xp40Activity.this, "L40");
        } else if (!SecretVault.stolen) {
            status.setText("尚未得手。\n提示：getStaticObjectField 读出私钥后记得调 reportStolenKey 回传。");
        }
    }
}
