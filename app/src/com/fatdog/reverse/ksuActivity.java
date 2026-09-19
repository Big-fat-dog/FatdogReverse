package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

// 天地秘境·九幽 KL49「盘根错节」：新一代 root（KernelSU/APatch）检测 + Play Integrity 本地仿真。
// 面具之外的根，藏在内核的名字里；它不落盘的仆从，躲在更深的角落。
// 还有一纸"身份证明"，盖着设备是否干净的章。
// 通关 = 让这套体检误判你是"原厂内核、无新一代 root、身份证明完好"的干净设备。
public class ksuActivity extends Activity {

    private TextView statusText;
    private final TextView[] signalCells = new TextView[6];
    private Button submitBtn;

    private static final String[] SIGNAL_NAMES = {
            "内核版本串", "内核 root 目录", "环境变量", "挂载点", "身份证明", "Magisk 兜底"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("九幽 KL49 · 盘根错节\n\n"
                + "面具之外的根，把名字刻进了内核；\n"
                + "它不落盘的仆从，躲进更深的角落。\n"
                + "还有一纸身份证明，\n"
                + "盖着设备是否干净的章。\n\n"
                + "六道信号，一道都别让它坐实。");
        tv.setGravity(Gravity.CENTER);
        box.addView(tv, Ui.wrap(6));

        statusText = new TextView(this);
        statusText.setText("尚未检测");
        statusText.setGravity(Gravity.CENTER);
        statusText.setTextColor(ThemeKit.muted(ThemeKit.isDark(this)));
        box.addView(statusText, Ui.wrap(6));

        LinearLayout signalBox = new LinearLayout(this);
        signalBox.setOrientation(LinearLayout.VERTICAL);
        signalBox.setGravity(Gravity.CENTER_HORIZONTAL);
        for (int i = 0; i < 6; i++) {
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
                if (runDetection(true)) {
                    Celebration.show(ksuActivity.this, "FLAG_19_KL49{sealed_integrity}");
                    PassLog.mark(ksuActivity.this, "KL49");
                }
            }
        });
        box.addView(submitBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(ksuActivity.this)
                        .setTitle("提示")
                        .setMessage("面具之外的根，往往不落盘、不露仆从——\n"
                                + "它把名字刻进了内核念出的那串版本里，\n"
                                + "把信物藏进更深一层的目录。\n\n"
                                + "还有一纸身份证明，盖着设备是否干净的章，\n"
                                + "谁动了那枚章，谁就露了马脚。\n\n"
                                + "想让它们全噤声：\n"
                                + "要么抹去内核里的名字与深层的信物，\n"
                                + "要么让那枚章，看起来依然完好。\n\n"
                                + "记住：单独抹掉一处不够，它用的是多数决。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kl49, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }

    // 跑一次完整检测。force = 是否复测（提交门）。返回是否"干净"。
    private boolean runDetection(boolean force) {
        int bitmap;
        try {
            bitmap = KernelGuard.nativeFullCheck();
        } catch (Throwable t) {
            statusText.setText("检测不可用：" + t.getMessage());
            return false;
        }

        int hits = 0;
        for (int i = 0; i < 6; i++) {
            boolean on = (bitmap & (1 << i)) != 0;
            if (on) hits++;
            signalCells[i].setText(SIGNAL_NAMES[i] + (on ? "：命中" : "：未命中"));
            signalCells[i].setTextColor(on ? 0xFFFB7299 : 0xFF67C23A);
        }

        int tampered;
        try {
            tampered = KernelGuard.nativeIsTampered(bitmap);
        } catch (Throwable t) {
            tampered = 0;
        }

        boolean clean = (tampered == 0);

        if (clean) {
            statusText.setText("体检通过——它把你看成了一台原厂内核的干净设备。");
            statusText.setTextColor(0xFF67C23A);
            submitBtn.setEnabled(true);
        } else {
            statusText.setText("检测到 " + hits + " 处可疑痕迹（阈值 2）。");
            statusText.setTextColor(0xFFFB7299);
            submitBtn.setEnabled(false);
            new AlertDialog.Builder(this)
                    .setTitle("检测到风险环境")
                    .setMessage("应用检测到当前设备可能存在新一代 root（KernelSU/APatch）或身份证明被篡改。\n"
                            + "命中信号数：" + hits + " / 6（阈值 2）。\n\n"
                            + "（这是警示弹窗，不会锁死关卡——继续绕，把它骗过去。）")
                    .setPositiveButton("知道了", null)
                    .show();
        }
        return clean;
    }
}
