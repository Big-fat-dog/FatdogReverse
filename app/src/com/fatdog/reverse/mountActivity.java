package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

// 天地秘境·九幽 KL48「斩草除根」：挂载点 / mount namespace 深检 + magiskd 进程检测。
// Magisk 是 systemless——不落盘改系统，而是运行时用 tmpfs 覆盖挂载，
// 所以翻文件查不到，得查"挂载表里的覆盖痕迹"和"藏起来的守护进程"。
// 通关 = 让这套体检误判你是"原厂挂载、无注入进程"的干净设备。
public class mountActivity extends Activity {

    private TextView statusText;
    private final TextView[] signalCells = new TextView[7];
    private Button submitBtn;

    private static final String[] SIGNAL_NAMES = {
            "挂载覆盖痕迹", "Magisk 挂载点", "dex2oat 环挂载", "守护进程", "挂载表字样", "环境变量", "原生桥/模块"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("九幽 KL48 · 斩草除根\n\n"
                + "它不落地的根，藏在你看不见的挂载表里；\n"
                + "它不露面的仆从，躲在进程的暗处。\n\n"
                + "这一次，去翻那张挂载的账本，\n"
                + "去听那些沉默进程的名字——\n"
                + "七道信号，一道都别让它坐实。");
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
                    Celebration.show(mountActivity.this, "FLAG_19_KL48{chains_broken}");
                    PassLog.mark(mountActivity.this, "KL48");
                }
            }
        });
        box.addView(submitBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(mountActivity.this)
                        .setTitle("提示")
                        .setMessage("它不落盘，所以地上没有痕迹——\n"
                                + "真正的痕迹，挂在运行时的那张挂载账本上，\n"
                                + "和那些沉默运行的仆从身上。\n\n"
                                + "想让它全噤声：\n"
                                + "要么把账本上的那几行抹去，\n"
                                + "要么让它看不见那几个仆从。\n\n"
                                + "记住：单独抹掉一处不够，它用的是多数决。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kl48, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }

    // 跑一次完整检测。force = 是否复测（提交门）。返回是否"干净"。
    private boolean runDetection(boolean force) {
        int bitmap;
        try {
            bitmap = MountGuard.nativeFullCheck();
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
            tampered = MountGuard.nativeIsTampered(bitmap);
        } catch (Throwable t) {
            tampered = 0;
        }

        boolean clean = (tampered == 0);

        if (clean) {
            statusText.setText("体检通过——它把你看成了一台原厂挂载的干净设备。");
            statusText.setTextColor(0xFF67C23A);
            submitBtn.setEnabled(true);
        } else {
            statusText.setText("检测到 " + hits + " 处可疑痕迹（阈值 2）。");
            statusText.setTextColor(0xFFFB7299);
            submitBtn.setEnabled(false);
            new AlertDialog.Builder(this)
                    .setTitle("检测到风险环境")
                    .setMessage("应用检测到当前设备存在隐藏挂载或注入进程。\n"
                            + "命中信号数：" + hits + " / 7（阈值 2）。\n\n"
                            + "（这是警示弹窗，不会锁死关卡——继续绕，把它骗过去。）")
                    .setPositiveButton("知道了", null)
                    .show();
        }
        return clean;
    }
}
