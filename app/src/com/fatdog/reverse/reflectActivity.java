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
 * KL40 星河倒影（碧落天 · 综合收官卷）
 *
 * 考点：
 *   1. 多层安全叠加——AOT 加密 + FFI + Isolate 签名 + 证书锁定 + RC4
 *   2. 任一层被绕过即静默投毒
 *   3. 反调试（ptrace + timing）+ 自校验
 *   4. 响应体 RC4 加密
 *
 * 破解路线：
 *   ① 逐层突破：反调试 → FFI 边界 → Dart 签名 → 响应解密
 *   ② Frida 全家桶：spawn 抢跑 + 多层 hook
 *   ③ Python 静态完整复刻（最稳）
 *   ④ patch so 废反调试 + 改比较点
 *
 * 标记：Fatdog_reflect（真）/ Fatdog_echo（诱饵）
 */
public class reflectActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("碧落天 KL40 · 星河倒影（★★★★★）\n\n" +
                "星河倒映层层深渊，六重防线交织如网。\n" +
                "AOT 加密、FFI 边界、Isolate 签名、证书锁定、RC4 响应——\n" +
                "任一层失守，整条链即刻崩塌投毒。\n" +
                "唯有逐层击破，方能窥见星河真容。\n\n" +
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

        // 全链签名按钮
        Button signBtn = new Button(this);
        signBtn.setText("全链签名（综合安全）");
        Ui.styleButton(signBtn);
        signBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long ts = System.currentTimeMillis() / 1000;
                String sign = FlutterMirror.nativeFullSign(1, ts);
                statusTv.setText("签名: " + sign.substring(0, Math.min(32, sign.length())) + "...");
            }
        });
        root.addView(signBtn, Ui.wrap(10));

        // 自校验按钮
        Button integrityBtn = new Button(this);
        integrityBtn.setText("代码完整性校验");
        Ui.styleButton(integrityBtn);
        integrityBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                boolean ok = FlutterMirror.nativeVerifyIntegrity();
                statusTv.setText("完整性校验: " + (ok ? "通过" : "失败（代码被篡改）"));
            }
        });
        root.addView(integrityBtn, Ui.wrap(10));

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
                String expected = FlutterMirror.nativeAnswer();
                if (input.equalsIgnoreCase(expected)) {
                    Celebration.show(reflectActivity.this, "FLAG_18_KL40{galaxy_reflected}");
                    PassLog.mark(reflectActivity.this, "KL40");
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
                new android.app.AlertDialog.Builder(reflectActivity.this)
                    .setTitle("提示")
                    .setMessage("六重防线如星河倒影，层层叠叠。\n\n" +
                                "反调试是第一道门槛，自校验是第二道屏障。\n" +
                                "AOT 加密与 FFI 边界交织，Dart 签名在深处守望。\n" +
                                "证书锁定如灯塔，RC4 响应如迷雾。\n\n" +
                                "两个标记一真一假，仔细辨别拼写差异。\n" +
                                "Python 静态复刻是最稳妥的破解路线——\n" +
                                "逐层还原密钥派生链，复刻签名与解密。")
                    .setPositiveButton("知道了", null)
                    .show();
            }
        });
        root.addView(hintBtn, Ui.wrap(8));

        // banner 图片
        root.addView(Ui.banner(this, R.drawable.level_kl40, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
