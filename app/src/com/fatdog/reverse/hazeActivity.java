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
 * KL38 雾里观花（碧落天 · Flutter 网络层 Hook）
 *
 * 考点：
 *   1. Flutter 自定义 HttpClient 请求构建与拦截
 *   2. Dart 层 SSL Pinning（证书 SHA-256 校验）
 *   3. Dart Isolate 内签名计算 + FFI 边界
 *   4. 反调试检测 + 静默投毒
 *
 * 破解路线：
 *   ① Frida hook libflutter.so 的 Dart_Invoke 系列函数
 *   ② 绕过 Dart 层 SSL Pinning
 *   ③ 拦截 Isolate 间消息获取密钥
 *   ④ Python 复刻 HMAC-SHA256 签名
 *
 * 标记：Fatdog_haze（真）/ Fatdog_fog（诱饵）
 */
public class hazeActivity extends Activity {

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
        tv.setText("碧落天 KL38 · 雾里观花（★★★）\n\n" +
                "雾气弥漫的网络层，Flutter 引擎自行构建 HTTP 请求。\n" +
                "证书锁定如迷雾中的灯塔，签名在 Dart Isolate 深处计算。\n" +
                "唯有穿透迷雾，识破网络层的真实面目。\n\n" +
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

        // 构建请求按钮
        Button buildBtn = new Button(this);
        buildBtn.setText("构建网络请求");
        Ui.styleButton(buildBtn);
        buildBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long ts = System.currentTimeMillis() / 1000;
                byte[] req = FlutterNet.nativeBuildRequest(1, ts);
                String pin = FlutterNet.nativeGetPinHash();
                statusTv.setText("请求参数: " + req.length + " 字节\nSSL Pin: " + pin);
            }
        });
        root.addView(buildBtn, Ui.wrap(10));

        // 哨兵自检按钮
        Button statusBtn = new Button(this);
        statusBtn.setText("哨兵自检");
        Ui.styleButton(statusBtn);
        statusBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String status = FlutterNet.nativeGetStatus();
                new android.app.AlertDialog.Builder(hazeActivity.this)
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
                String expected = FlutterNet.nativeAnswer();
                if (input.equalsIgnoreCase(expected)) {
                    Celebration.show(hazeActivity.this, "FLAG_18_KL38{flower_in_mist}");
                    PassLog.mark(hazeActivity.this, "KL38");
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
                new android.app.AlertDialog.Builder(hazeActivity.this)
                    .setTitle("提示")
                    .setMessage("Flutter 引擎绕过 Java 网络栈，自行构建 HTTP 请求。\n\n" +
                                "迷雾之中，两个标记若隐若现——\n" +
                                "一个是网络层的真面目，一个是海市蜃楼。\n" +
                                "仔细辨别拼写差异，穿透迷雾方见真章。\n\n" +
                                "密钥藏于网络层深处，签名在 Dart 世界中诞生。")
                    .setPositiveButton("知道了", null)
                    .show();
            }
        });
        root.addView(hintBtn, Ui.wrap(8));

        // banner 图片（固定在最底部）
        root.addView(Ui.banner(this, R.drawable.level_kl38, 140));

        // 设置内容视图（包裹在 ScrollView 中）
        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
