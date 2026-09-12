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
 * KL37 风中鸢尾（碧落天 · Dart Kernel 字节码逆向）
 *
 * 考点：
 *   1. 识别 Dart Kernel 字节码格式（Drt\0 魔数 + 指令序列）
 *   2. 逆向字节码中的 HMAC 签名计算逻辑
 *   3. 提取异或加密的常量池密钥
 *   4. 应对四路哨兵反逆向（ptrace/maps/端口/线程名）
 *   5. 绕过 CRC 自校验（或 hook 校验器）
 *
 * 反逆向对抗（四路哨兵 + CRC）：
 *   - ptrace/TracerPid 检测调试附加
 *   - /proc/self/maps 扫描 Frida 特征
 *   - 27042-27044 端口探测
 *   - 线程名扫描（gum-js-loop/gmain 等）
 *   - 函数头 inline hook 检测
 *   - .text 段 CRC 自校验
 *   - 检测命中即静默投毒密钥，服务端 403
 *
 * 破解路线：
 *   ① Frida spawn 拆哨兵 → hook nativeExecute 拿签名 → Python 复刻
 *   ② IDA 读字节码 blob → 还原常量池 → 提取密钥 → Python 复刻
 *   ③ patch CRC 校验器 + 废哨兵 → 重打包
 *
 * 标记：Fatdog_kite（真）/ Fatdog_sail（诱饵）
 */
public class kiteActivity extends Activity {

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
        tv.setText("碧落天 KL37 · 风中鸢尾（★★）\n\n" +
                "鸢尾随风而舞，Kernel 字节码栖于 Flutter 引擎深处。\n" +
                "重重防线守护着签名密钥，唯有识破守护者的检测逻辑。\n" +
                "方能取回真钥，还原签名真身。\n\n" +
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

        // 获取字节码 blob 按钮
        Button blobBtn = new Button(this);
        blobBtn.setText("获取 Dart Kernel 字节码");
        Ui.styleButton(blobBtn);
        blobBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                byte[] blob = FlutterCore.nativeGetBytecodeBlob();
                String info = FlutterCore.nativeGetAlgorithmInfo();
                statusTv.setText("字节码大小: " + blob.length + " 字节\n算法: " + info);
            }
        });
        root.addView(blobBtn, Ui.wrap(10));

        // 查看哨兵状态按钮
        Button statusBtn = new Button(this);
        statusBtn.setText("哨兵自检");
        Ui.styleButton(statusBtn);
        statusBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String status = FlutterCore.nativeGetStatus();
                new android.app.AlertDialog.Builder(kiteActivity.this)
                    .setTitle("哨兵状态")
                    .setMessage(status)
                    .setPositiveButton("知道了", null)
                    .show();
            }
        });
        root.addView(statusBtn, Ui.wrap(10));

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
                String expected = FlutterCore.nativeAnswer();
                if (input.equalsIgnoreCase(expected)) {
                    Celebration.show(kiteActivity.this, "FLAG_18_KL37{iris_in_the_wind}");
                    PassLog.mark(kiteActivity.this, "KL37");
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
                new android.app.AlertDialog.Builder(kiteActivity.this)
                    .setTitle("提示")
                    .setMessage("Flutter 引擎深处，Dart Kernel 字节码沉睡于加密之中。\n\n" +
                                "重重防线守护着签名密钥——\n" +
                                "攻击者每进一步，守护者便多一分警觉。\n" +
                                "唯有识破守护者的检测逻辑，方能安全取钥。\n\n" +
                                "两个标记，一真一假，仔细辨别拼写差异。")
                    .setPositiveButton("知道了", null)
                    .show();
            }
        });
        root.addView(hintBtn, Ui.wrap(8));

        // banner 图片（固定在最底部）
        root.addView(Ui.banner(this, R.drawable.level_kl37, 140));

        // 设置内容视图（包裹在 ScrollView 中）
        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
