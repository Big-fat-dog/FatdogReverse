package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

// 天地秘境·九幽 KL47「深根固蒂」：Bootloader 解锁 + 系统属性深检。
// 真实 App 的风控标配——不是查你装了啥文件，而是问系统"你是谁、你被解锁过吗"。
// 七道信号都刻在系统属性与内核启动参数里，比文件更贴近机器的根。
// 通关 = 让这套体检误判你是"出厂锁定、未被改动的干净设备"。
public class bootActivity extends Activity {

    private TextView statusText;
    private final TextView[] signalCells = new TextView[7];
    private Button submitBtn;

    private static final String[] SIGNAL_NAMES = {
            "启动校验状态", "vbmeta 设备态", "安全锁状态", "内核启动参数", "调试属性", "原生桥", "自定义系统"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("九幽 KL47 · 深根固蒂\n\n"
                + "这一次，它不再翻找落地的痕迹，\n"
                + "而是直接问机器的根：\n"
                + "你被解锁过吗？你从哪里醒来？\n\n"
                + "七道信号，都刻在系统的骨血里——\n"
                + "比文件更贴近本质，也更难抹去。");
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
                if (runDetection(true)) {
                    Celebration.show(bootActivity.this, "FLAG_19_KL47{probing_the_depths}");
                    PassLog.mark(bootActivity.this, "KL47");
                }
            }
        });
        box.addView(submitBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(bootActivity.this)
                        .setTitle("提示")
                        .setMessage("七道信号，问的是机器自己的根——\n"
                                + "启动时校验过的状态、vbmeta 的设备态、安全锁、\n"
                                + "还有内核醒来时念出的那串启动参数。\n\n"
                                + "这些大多藏在系统属性里，只有一两处最硬——\n"
                                + "它由内核直接导出，寻常的改法抹不掉。\n\n"
                                + "想让它全噤声，要么伪造它念出的答案，\n"
                                + "要么让探路的手，看岔了方向。\n"
                                + "记住：单独抹掉一处不够，它用的是多数决。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kl47, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }

    // 跑一次完整检测。force = 是否复测（提交门）。返回是否"干净"。
    private boolean runDetection(boolean force) {
        int bitmap;
        try {
            bitmap = BootGuard.nativeFullCheck();
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

        int tampered;
        try {
            tampered = BootGuard.nativeIsTampered(bitmap);
        } catch (Throwable t) {
            tampered = 0;
        }

        boolean clean = (tampered == 0);

        if (clean) {
            statusText.setText("体检通过——它把你看成了一台未被改动的设备。");
            statusText.setTextColor(0xFF67C23A);
            submitBtn.setEnabled(true);
        } else {
            statusText.setText("检测到 " + hits + " 处可疑痕迹（阈值 2）。");
            statusText.setTextColor(0xFFFB7299);
            submitBtn.setEnabled(false);
            new AlertDialog.Builder(this)
                    .setTitle("检测到风险环境")
                    .setMessage("应用检测到当前设备可能已解锁 Bootloader 或系统被改动。\n"
                            + "命中信号数：" + hits + " / 7（阈值 2）。\n\n"
                            + "（这是警示弹窗，不会锁死关卡——继续绕，把它骗过去。）")
                    .setPositiveButton("知道了", null)
                    .show();
        }
        return clean;
    }
}
