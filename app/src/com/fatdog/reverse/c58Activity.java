package com.fatdog.reverse;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

/**
 * 扶桑树 KL21 枯叶听风：端口探测 + D-Bus 协议指纹。
 * libfox.so 导出五个函数：
 *   int    nativeFridaDetect()      — 综合检测（端口+D-Bus，OR 判定）
 *   int    nativePortScan()         — 端口探测子结果
 *   int    nativeDbusFingerprint()  — D-Bus 指纹子结果
 *   String nativeAnswer()           — 最终答案
 *   String nativeStatus()           — 检测详情
 *
 * 破解路线：① hook nativeFridaDetect 返回 0
 *           ② Frida 改端口避开 27042-27044
 *           ③ hook readlinkat 过滤 /proc/net/tcp
 *           ④ 静态复刻：IDA 提取 SHA-256(SEED=20280715) → 答案
 */
public class c58Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL21 · 枯叶听风（★ 扶桑树首关）\n\n"
                + "libfox.so 导出五个函数：\n"
                + "  int    nativeFridaDetect()\n"
                + "  int    nativePortScan()\n"
                + "  int    nativeDbusFingerprint()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "两路 Frida 检测（OR 判定）：\n"
                + "  ① 端口探测：connect 27042/27043/27044\n"
                + "  ② D-Bus 指纹：解析 /proc/net/tcp\n\n"
                + "标记：两个标记一真一假，需仔细辨别");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        // 检测状态按钮
        final TextView statusTv = new TextView(this);
        statusTv.setText("点击「运行检测」查看状态");
        statusTv.setTextColor(Color.LTGRAY);
        statusTv.setTypeface(Typeface.MONOSPACE);
        statusTv.setTextSize(12);
        statusTv.setGravity(Gravity.CENTER);
        root.addView(statusTv, Ui.fullWidth(6));

        Button runBtn = new Button(this);
        runBtn.setText("运行检测"); Ui.styleButton(runBtn);
        runBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                int result = Lk.nativeFridaDetect();
                String status = Lk.nativeStatus();
                statusTv.setText("检测结果: " + (result == 1 ? "检出 Frida" : "未检出") + "\n\n" + status);
                statusTv.setTextColor(result == 1 ? 0xFFFF6B6B : 0xFF51CF66);
            }
        });
        root.addView(runBtn, Ui.wrap(10));

        // 答案输入框
        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入答案（32位 hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        int p = Ui.dp(10);
        ansIn.setPadding(p, p, p, p);
        root.addView(ansIn, Ui.fullWidth(10));

        // 提交按钮
        Button subBtn = new Button(this);
        subBtn.setText("提交答案"); Ui.styleButton(subBtn);
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(c58Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Lk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(c58Activity.this, "FLAG_18_KL21{leaf_hears_the_wind}");
                    PassLog.mark(c58Activity.this, "KL21");
                } else {
                    Toast.makeText(c58Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        // 提示按钮
        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(c58Activity.this)
                        .setTitle("提示")
                        .setMessage("扶桑树首关——端口探测 + D-Bus 协议指纹：\n\n"
                                + "① 端口探测：connect() 27042/27043/27044，Frida 默认监听端口\n"
                                + "② D-Bus 指纹：解析 /proc/net/tcp，查找 loopback ESTABLISHED 连接\n\n"
                                + "两路 OR 判定——任一检出即判定。\n\n"
                                + "绕过路线：\n"
                                + "  • hook nativeFridaDetect 返回 0\n"
                                + "  • Frida 修改监听端口\n"
                                + "  • NOP 端口检测代码\n\n"
                                + "静态复刻路线：\n"
                                + "  • IDA 分析 → 提取 SHA-256(SEED)\n"
                                + "  • SEED = 20280715\n"
                                + "  • 答案 = sha256(0x{SEED的4字节大端表示})\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        // banner
        root.addView(Ui.banner(this, R.drawable.level_kl21, 140));

        setContentView(root);
        ThemeKit.apply(this);
    }
}
