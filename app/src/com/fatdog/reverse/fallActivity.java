package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

// 天地秘境·九幽 KL46「落叶归根」：Root 检测与绕过（多层环境检测入门）。
// 真实 App 启动时常做的"环境体检"：SU/Magisk 文件、高危包名、系统属性、
// SELinux、挂载点…… 本关把它们拆成七道信号，逐一真实探测。
// 通关 = 让这套体检"误判你是一台干净设备"——全部信号都不命中。
// 检测到风险会弹窗警告，但不锁死；提交时再复测一次（双门）。
public class fallActivity extends Activity {

    private TextView statusText;
    private final TextView[] signalCells = new TextView[7];
    private Button submitBtn;
    private boolean lastClean = false;

    private static final String[] SIGNAL_NAMES = {
            "SU 文件", "Magisk 文件", "高危包名", "系统属性", "SELinux", "挂载点", "系统调用复查"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("九幽 KL46 · 落叶归根\n\n"
                + "这是一次真实的环境体检：\n"
                + "它从七个角落悄悄打量你脚下这片土地，\n"
                + "看是否有不该留下的根系。\n\n"
                + "让它把你看成一片干净的落叶吧——\n"
                + "七道信号，一道都别露。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        statusText = new TextView(this);
        statusText.setText("尚未检测");
        statusText.setGravity(Gravity.CENTER);
        statusText.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(statusText, Ui.wrap(6));

        // 七道信号逐项显示
        LinearLayout signalBox = new LinearLayout(this);
        signalBox.setOrientation(LinearLayout.VERTICAL);
        signalBox.setGravity(Gravity.CENTER_HORIZONTAL);
        for (int i = 0; i < 7; i++) {
            TextView c = new TextView(this);
            c.setText(SIGNAL_NAMES[i] + "：—");
            c.setGravity(Gravity.CENTER);
            c.setTextSize(13);
            c.setTypeface(android.graphics.Typeface.MONOSPACE);
            c.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
            signalBox.addView(c, Ui.wrap(2));
            signalCells[i] = c;
        }
        box.addView(signalBox, Ui.fullWidth(8));

        Button detect = new Button(this);
        detect.setText("开始检测");
        Ui.styleButton(detect);
        detect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                runDetection(false);
            }
        });
        box.addView(detect, Ui.wrap(10));

        submitBtn = new Button(this);
        submitBtn.setText("提交通关");
        Ui.styleButton(submitBtn);
        submitBtn.setEnabled(false);
        submitBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // 双门：提交时复测，仍全绿才放行。
                if (runDetection(true)) {
                    Celebration.show(fallActivity.this, "FLAG_19_KL46{guard_at_the_gate}");
                    PassLog.mark(fallActivity.this, "KL46");
                }
            }
        });
        box.addView(submitBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(fallActivity.this)
                        .setTitle("提示")
                        .setMessage("七道信号都真实探过了一遍——有的走文件、有的走属性、\n"
                                + "有的甚至绕过常路直取内核。\n\n"
                                + "想让它们全部噤声，有几条路可走：\n"
                                + "把那些被点名的地方藏起来；\n"
                                + "或让探路的那双手，看岔了方向。\n\n"
                                + "记住：单独藏掉一两处不够，它用的是多数决。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kl46, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }

    // 跑一次完整检测。force = 是否复测（提交门）。
    // 返回是否"干净"（全部信号未命中）。
    private boolean runDetection(boolean force) {
        int bitmap;
        try {
            bitmap = RootSentinel.nativeFullCheck();
        } catch (Throwable t) {
            statusText.setText("检测不可用：" + t.getMessage());
            return false;
        }

        int hits = 0;
        for (int i = 0; i < 7; i++) {
            boolean on = (bitmap & (1 << i)) != 0;
            if (on) hits++;
            signalCells[i].setText(SIGNAL_NAMES[i] + (on ? "：命中" : "：未命中"));
            signalCells[i].setTextColor(on ? 0xFFFB7299 : 0xFF67C23A);
        }

        int rooted;
        try {
            rooted = RootSentinel.nativeIsRooted(bitmap);
        } catch (Throwable t) {
            rooted = 0;
        }

        boolean clean = (rooted == 0);
        lastClean = clean;

        if (clean) {
            statusText.setText("体检通过——它把你当成了一台干净设备。");
            statusText.setTextColor(0xFF67C23A);
            submitBtn.setEnabled(true);
        } else {
            statusText.setText("检测到 " + hits + " 处可疑痕迹（阈值 3）。");
            statusText.setTextColor(0xFFFB7299);
            submitBtn.setEnabled(false);
            // 弹窗警告（不锁死，模拟真实 App 启动时的风险提示）
            new AlertDialog.Builder(this)
                    .setTitle("检测到风险环境")
                    .setMessage("应用检测到当前设备可能已被 Root 或存在注入痕迹。\n"
                            + "命中信号数：" + hits + " / 7（阈值 3）。\n\n"
                            + "（这是警示弹窗，不会锁死关卡——继续绕，把它骗过去。）")
                    .setPositiveButton("知道了", null)
                    .show();
        }
        return clean;
    }
}
