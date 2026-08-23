package com.fatdog.reverse;


import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

// L39 偷梁换柱：verifyDevice(deviceId) 用 SHA256 比对内置哈希。
// 玩家需先通过 jadx 找到正确 deviceId（"fatdog_xp_2026"），
// 再用 beforeHookedMethod 篡改 args[0] 为正确值。
public class xp39Activity extends Activity {

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
        tv.setText("Xposed 第二关 · 偷梁换柱\n\n"
                + "本页有一个方法 verifyDevice(String deviceId)。\n"
                + "它将 deviceId 的 SHA256 与内置值比对，匹配则返回 true。\n"
                + "正确的 deviceId 藏在源码的另一个类里——先用 jadx 找到它，\n"
                + "然后用 beforeHookedMethod 篡改参数为正确值。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        status = new TextView(this);
        status.setText("检测中…");
        status.setTextSize(16);
        status.setGravity(Gravity.CENTER);
        status.setPadding(0, Ui.dp(20), 0, Ui.dp(20));
        box.addView(status, Ui.wrap(4));

        box.addView(Ui.banner(this, R.drawable.level_39, 140));

        setContentView(box);
        ThemeKit.apply(this);

        // 触发验证——如果玩家 Hook 了 before 并替换了参数，这里会返回 true
        boolean ok = XpVerifier.verifyDevice("random_device_12345");
        if (ok && !passed) {
            passed = true;
            status.setText("✓ 设备验证通过！Hook 生效。");
            Celebration.show(xp39Activity.this, "FLAG_18_L39{swap_the_argument}");
            PassLog.mark(xp39Activity.this, "L39");
        } else if (!ok) {
            status.setText("verifyDevice 返回 false。\n提示：jadx 里搜 FatdogXP 类找到正确 deviceId。");
        }
    }
}
