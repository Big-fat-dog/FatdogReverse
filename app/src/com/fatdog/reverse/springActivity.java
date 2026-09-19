package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

// 天地秘境·九幽 KL50「枯木逢春」：综合收官卷。
// 前面四关的检测，在这里汇总成一次"全身体检"。
// 但它会骗你——第一次检测，它把真相藏了起来，只给你看一片看似干净；
// 直到你提交的那一刻，它才把藏着的东西，一件件摆到你面前。
// 通关 = 识破它的静默，让这八道信号，一道都别坐实。
public class springActivity extends Activity {

    private TextView statusText;
    private final TextView[] signalCells = new TextView[8];
    private Button submitBtn;

    private static final String[] SIGNAL_NAMES = {
            "su 文件", "Magisk 文件", "启动校验", "内核启动参数",
            "挂载覆盖", "守护进程", "内核版本串", "内核 root 目录"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setGravity(Gravity.CENTER_HORIZONTAL);
        box.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("九幽 KL50 · 枯木逢春\n\n"
                + "前面四关的问询，在这里汇成一场全身体检——\n"
                + "它问你的文件、问你的根、问你的锁、问你内核的名字。\n\n"
                + "但它会骗你：\n"
                + "第一次，它把真相藏起来，只给你看一片假意的干净；\n"
                + "直到你交出答案的那一刻，\n"
                + "它才把藏着的东西，一件件摆到你面前。\n\n"
                + "识破它的静默，八道信号，一道都别坐实。");
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
        for (int i = 0; i < 8; i++) {
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
                // 静默投毒：nativeDetect 返回看似干净的 0
                try {
                    int fake = RootSpring.nativeDetect();
                    // 假象：全绿
                    for (int i = 0; i < 8; i++) {
                        signalCells[i].setText(SIGNAL_NAMES[i] + "：未命中");
                        signalCells[i].setTextColor(0xFF67C23A);
                    }
                    statusText.setText("体检通过——它说，你是一台干净的设备。");
                    statusText.setTextColor(0xFF67C23A);
                    submitBtn.setEnabled(true);
                } catch (Throwable t) {
                    statusText.setText("检测不可用：" + t.getMessage());
                }
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
                // 提交复测：nativeVerify 返回真实位图，露馅
                int real;
                try {
                    real = RootSpring.nativeVerify();
                } catch (Throwable t) {
                    statusText.setText("检测不可用：" + t.getMessage());
                    return;
                }
                int hits = 0;
                for (int i = 0; i < 8; i++) {
                    boolean on = (real & (1 << i)) != 0;
                    if (on) hits++;
                    signalCells[i].setText(SIGNAL_NAMES[i] + (on ? "：命中" : "：未命中"));
                    signalCells[i].setTextColor(on ? 0xFFFB7299 : 0xFF67C23A);
                }
                int tampered;
                try {
                    tampered = RootSpring.nativeIsTampered(real);
                } catch (Throwable t) {
                    tampered = 0;
                }
                if (tampered == 0) {
                    // 真实干净 → 通关
                    Celebration.show(springActivity.this, "FLAG_19_KL50{spring_after_winter}");
                    PassLog.mark(springActivity.this, "KL50");
                } else {
                    // 露馅：真实环境有风险
                    statusText.setText("真相大白——检测到 " + hits + " 处可疑痕迹。");
                    statusText.setTextColor(0xFFFB7299);
                    new AlertDialog.Builder(springActivity.this)
                            .setTitle("检测到风险环境")
                            .setMessage("第一次的干净是假象。\n"
                                    + "真实命中信号数：" + hits + " / 8（阈值 3）。\n\n"
                                    + "它把真相藏在了提交这一刻——继续绕，把八道都压下去。")
                            .setPositiveButton("知道了", null)
                            .show();
                }
            }
        });
        box.addView(submitBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示");
        hint.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new AlertDialog.Builder(springActivity.this)
                        .setTitle("提示")
                        .setMessage("八道信号，是前面四场问询的合体——\n"
                                + "问文件、问根、问锁、问内核的名字。\n\n"
                                + "但最要防的，是它的静默：\n"
                                + "第一次的干净，可能是假意；\n"
                                + "真正的答案，藏在你要交卷的那一刻。\n\n"
                                + "别被第一次的绿色骗了，\n"
                                + "去把八道都真正压下去。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        box.addView(hint, Ui.wrap(8));

        box.addView(Ui.banner(this, R.drawable.level_kl50, 140));

        setContentView(Ui.wrapScroll(box));
        ThemeKit.apply(this);
    }
}
