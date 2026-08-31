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
 * 扶桑树 KL27 轻纱覆影：OR 判定。
 * libveil.so 导出五个函数：
 *   int    nativeThreadContext()   — 线程上下文指纹
 *   int    nativeTimingCrossref()  — 时序交叉验证
 *   int    nativeFridaDetect()     — 综合检测（OR）
 *   String nativeAnswer()          — 最终答案
 *   String nativeStatus()          — 检测详情
 */
public class i64Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL27 · 轻纱覆影（★★☆ 交叉验证）\n\n"
                + "libveil.so 导出五个函数：\n"
                + "  int    nativeThreadContext()\n"
                + "  int    nativeTimingCrossref()\n"
                + "  int    nativeFridaDetect()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "OR 判定（任一触发即判定）：\n"
                + "  ① 线程上下文指纹\n"
                + "  ② 时序交叉验证\n\n"
                + "标记：两个标记一真一假，需仔细辨别");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

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
                int result = Vk27.nativeFridaDetect();
                String status = Vk27.nativeStatus();
                statusTv.setText("检测结果: " + (result == 1 ? "检出 Frida" : "未检出") + "\n\n" + status);
                statusTv.setTextColor(result == 1 ? 0xFFFF6B6B : 0xFF51CF66);
            }
        });
        root.addView(runBtn, Ui.wrap(10));

        final EditText ansIn = new EditText(this);
        ansIn.setHint("输入答案（32位 hex）");
        ansIn.setTextColor(Color.WHITE);
        ansIn.setTypeface(Typeface.MONOSPACE);
        ansIn.setBackgroundColor(0x33FFFFFF);
        int p = Ui.dp(10);
        ansIn.setPadding(p, p, p, p);
        root.addView(ansIn, Ui.fullWidth(10));

        Button subBtn = new Button(this);
        subBtn.setText("提交答案"); Ui.styleButton(subBtn);
        subBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String ans = ansIn.getText().toString().trim();
                if (ans.isEmpty()) { Toast.makeText(i64Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Vk27.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(i64Activity.this, "FLAG_18_KL27{veil_conceals_all}");
                    PassLog.mark(i64Activity.this, "KL27");
                } else {
                    Toast.makeText(i64Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(i64Activity.this)
                        .setTitle("提示")
                        .setMessage("交叉验证双重检测：\n\n"
                                + "① 线程上下文指纹（/proc/self/task）\n"
                                + "② 时序交叉验证（dlopen vs malloc 延迟比）\n\n"
                                + "OR 判定：任一触发即判定 Frida 存在\n\n"
                                + "绕过路线：\n"
                                + "  • 两路都需绕过\n"
                                + "  • 挂钩线程名/时序测量\n\n"
                                + "静态复刻：SEED = 20280721\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl27, 140));

        setContentView(root);
        ThemeKit.apply(this);
    }
}
