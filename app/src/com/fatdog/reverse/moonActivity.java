package com.fatdog.reverse;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * KL39 月下独酌（碧落天 · Dart FFI 双向往调）
 *
 * 考点：
 *   1. Dart FFI 双向往调——Dart→C 加密，C→Dart 取密钥碎片
 *   2. 密钥分两侧各存一半，运行时拼装
 *   3. FFI 函数注册表（DartNativeFunction 数组）逆向
 *   4. 反调试检测 + 静默投毒
 *
 * 破解路线：
 *   ① IDA 分析 FFI 函数注册表（DartNativeFunction 数组）
 *   ② Hook dart:ffi 边界函数
 *   ③ 提取两侧密钥碎片 → 拼装 → Python 复刻
 *   ④ Frida hook nativeDeriveKey 直接拿完整密钥
 *
 * 标记：Fatdog_moon（真）/ Fatdog_star（诱饵）
 */
public class moonActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("碧落天 KL39 · 月下独酌（★★★★）\n\n" +
                "月光洒落 FFI 边界，Dart 与 C 两岸各执一片密钥碎片。\n" +
                "唯有跨越语言边界，将碎片拼合，方能窥见完整密钥。\n" +
                "函数注册表中暗藏玄机，反调试哨兵静默守望。\n\n" +
                "求取数字，提交答案。");
        tv.setTextSize(14);
        tv.setTextColor(Color.WHITE);
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        final TextView statusTv = new TextView(this);
        statusTv.setText("就绪");
        statusTv.setTextSize(12);
        statusTv.setTextColor(Color.LTGRAY);
        statusTv.setTypeface(Typeface.MONOSPACE);
        root.addView(statusTv, Ui.fullWidth(6));

        // FFI 加密请求按钮
        Button encBtn = new Button(this);
        encBtn.setText("构建 FFI 加密请求");
        Ui.styleButton(encBtn);
        encBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long ts = System.currentTimeMillis() / 1000;
                byte[] enc = FlutterFFI.nativeEncRequest(1, ts);
                statusTv.setText("FFI 加密参数: " + enc.length + " 字节\n时间戳: " + ts);
            }
        });
        root.addView(encBtn, Ui.wrap(10));

        // 密钥派生按钮
        Button deriveBtn = new Button(this);
        deriveBtn.setText("密钥派生（C→Dart 回调）");
        Ui.styleButton(deriveBtn);
        deriveBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String key = FlutterFFI.nativeDeriveKey();
                statusTv.setText("拼装密钥: " + key);
            }
        });
        root.addView(deriveBtn, Ui.wrap(10));

        // 答案输入框
        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入答案（8位hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        root.addView(ansIn, Ui.fullWidth(10));

        // 提交按钮
        Button subBtn = new Button(this);
        subBtn.setText("提交答案");
        Ui.styleButton(subBtn);
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String input = ansIn.getText().toString().trim();
                String expected = FlutterFFI.nativeAnswer();
                if (input.equalsIgnoreCase(expected)) {
                    Celebration.show(moonActivity.this, "FLAG_18_KL39{drinking_alone_moonlight}");
                    PassLog.mark(moonActivity.this, "KL39");
                    statusTv.setText("恭喜通关！");
                } else {
                    statusTv.setText("答案不对，请重试");
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        // 提示按钮
        Button hintBtn = new Button(this);
        hintBtn.setText("提示");
        Ui.styleButton(hintBtn);
        hintBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new android.app.AlertDialog.Builder(moonActivity.this)
                    .setTitle("提示")
                    .setMessage("Dart FFI 边界是 Dart 与 C 之间的桥梁。\n\n" +
                                "月色之下，两片碎片若隐若现——\n" +
                                "一片藏在 Dart 世界，一片藏在 C 的领地。\n" +
                                "函数注册表是 FFI 的命脉，IDA 中可见其真容。\n\n" +
                                "两个标记一真一假，仔细辨别拼写差异。\n" +
                                "Frida 可直取拼装后的完整密钥。")
                    .setPositiveButton("知道了", null)
                    .show();
            }
        });
        root.addView(hintBtn, Ui.wrap(8));

        // banner 图片
        root.addView(Ui.banner(this, R.drawable.level_kl39, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
