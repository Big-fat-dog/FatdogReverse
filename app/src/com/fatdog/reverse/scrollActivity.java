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
 * 碧落天 KL36 · 云中锦书（★）
 * Flutter/Dart 逆向入门：Dart AOT 快照基础
 * 
 * libflutterbridge.so 导出函数：
 *   nativeGetConstantPool() → 返回模拟的 Dart 常量池 byte[]
 *   nativeSign(page, ts) → 用提取的密钥计算 HMAC-SHA256
 *   nativeVerify(page, ts, sign) → 验证签名
 *   nativeAnswer() → 返回答案
 * 
 * 考点：
 *   1. IDA 定位 .rodata 段中的密钥（异或数组）
 *   2. 运行时解码密钥 → Python 复刻 HMAC-SHA256
 *   3. Frida hook nativeSign 观察入参出参
 * 
 * 标记：Fatdog_scroll（真）/ Fatdog_roll（诱饵）
 */
public class scrollActivity extends Activity {
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // 根布局（遵循 KL 活动页 UI 排版规范）
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));
        
        // 顶部说明文字
        TextView tv = new TextView(this);
        tv.setText("碧落天 KL36 · 云中锦书（★）\n\n" +
                "锦书自天外飞来，封蜡之上隐有异文。\n" +
                "传闻此信需以 Flutter 之力方能启封——\n" +
                "信使已将密语藏于桥石之中，待有缘人 decipher。\n\n" +
                "求取数字，提交答案。");
        tv.setTextSize(14);
        tv.setTextColor(Color.WHITE);
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));
        
        // 状态显示
        final TextView statusTv = new TextView(this);
        statusTv.setText("就绪");
        statusTv.setTextSize(12);
        statusTv.setTextColor(Color.LTGRAY);
        statusTv.setTypeface(Typeface.MONOSPACE);
        root.addView(statusTv, Ui.fullWidth(6));
        
        // 获取常量池按钮
        Button poolBtn = new Button(this);
        poolBtn.setText("获取常量池");
        Ui.styleButton(poolBtn);
        poolBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                byte[] pool = FlutterBridge.nativeGetConstantPool();
                statusTv.setText("常量池大小: " + pool.length + " 字节");
            }
        });
        root.addView(poolBtn, Ui.wrap(10));
        
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
                String expected = FlutterBridge.nativeAnswer();
                if (input.equalsIgnoreCase(expected)) {
                    Celebration.show(scrollActivity.this, "FLAG_18_KL36{cloud_letter_unrolled}");
                    PassLog.mark(scrollActivity.this, "KL36");
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
                new android.app.AlertDialog.Builder(scrollActivity.this)
                    .setTitle("提示")
                    .setMessage("Flutter 桥石之中，数据以密文形态栖居。\n" +
                                "试着用动态分析的手段，看看桥石在\n" +
                                "运行时吐出了什么——明文往往只在一念之间。")
                    .setPositiveButton("知道了", null)
                    .show();
            }
        });
        root.addView(hintBtn, Ui.wrap(8));
        
        // banner 图片（固定在最底部）
        root.addView(Ui.banner(this, R.drawable.level_kl36, 140));
        
        // 设置内容视图（包裹在 ScrollView 中）
        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
