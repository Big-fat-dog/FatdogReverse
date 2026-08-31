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
 * 天机阁 KL29 暗流涌动：TLV 二进制协议——OR 判定。
 * libtide.so 导出五个函数：
 *   int    nativeTlvMagic()     — TLV magic 校验
 *   int    nativePtrace()       — ptrace 反附加
 *   int    nativeFridaDetect()  — 综合检测（OR）
 *   String nativeAnswer()       — 最终答案
 *   String nativeStatus()       — 检测详情
 */
public class tideActivity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL29 · 暗流涌动（★ TLV 二进制协议）\n\n"
                + "libtide.so 导出五个函数：\n"
                + "  int    nativeTlvMagic()\n"
                + "  int    nativePtrace()\n"
                + "  int    nativeFridaDetect()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "OR 判定（任一触发即判定）：\n"
                + "  ① TLV 帧 magic 校验\n"
                + "  ② ptrace 反附加检测\n\n"
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
                int result = Ak29.nativeFridaDetect();
                String status = Ak29.nativeStatus();
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
                if (ans.isEmpty()) { Toast.makeText(tideActivity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Ak29.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(tideActivity.this, "FLAG_18_KL29{surging_undercurrents}");
                    PassLog.mark(tideActivity.this, "KL29");
                } else {
                    Toast.makeText(tideActivity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(tideActivity.this)
                        .setTitle("提示")
                        .setMessage("TLV 二进制协议检测：\n\n"
                                + "① TLV 帧 magic 校验\n"
                                + "② ptrace 反附加检测\n\n"
                                + "OR 判定：任一触发即判定 Frida 存在\n\n"
                                + "绕过路线：\n"
                                + "  • 两路都需绕过\n"
                                + "  • 挂钩 TLV magic 校验 + ptrace 系统调用\n\n"
                                + "静态复刻：SEED = 20280723\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl29, 140));

        setContentView(root);
        ThemeKit.apply(this);
    }
}
