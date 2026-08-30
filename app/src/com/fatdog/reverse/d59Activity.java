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
 * 扶桑树 KL22 落影寻痕：/proc/self/fd 扫描 + maps 搜索。
 * libowl.so 导出五个函数：
 *   int    nativeFridaDetect()  — 综合检测（fd+maps，OR 判定）
 *   int    nativeFdScan()       — fd 扫描子结果
 *   int    nativeMapsScan()     — maps 搜索子结果
 *   String nativeAnswer()       — 最终答案
 *   String nativeStatus()       — 检测详情
 *
 * 破解路线：① hook nativeFridaDetect 返回 0
 *           ② hook readlinkat 返回假路径
 *           ③ hook opendir 过滤 fd
 *           ④ 静态复刻：IDA 提取 SHA-256(SEED=20280716)
 */
public class d59Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL22 · 落影寻痕（★★ fd 层检测）\n\n"
                + "libowl.so 导出五个函数：\n"
                + "  int    nativeFridaDetect()\n"
                + "  int    nativeFdScan()\n"
                + "  int    nativeMapsScan()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "两路 Frida 检测（OR 判定）：\n"
                + "  ① fd 扫描：readlink /proc/self/fd → memfd:frida-agent\n"
                + "  ② maps 搜索：/proc/self/maps 含 frida 字符串\n\n"
                + "标记：Fatdog_shadow（真）/ Fatdog_shade（假）");
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
                int result = Nk.nativeFridaDetect();
                String status = Nk.nativeStatus();
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
                if (ans.isEmpty()) { Toast.makeText(d59Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Nk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(d59Activity.this, "FLAG_18_KL22{shadow_leaves_no_trace}");
                    PassLog.mark(d59Activity.this, "KL22");
                } else {
                    Toast.makeText(d59Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(d59Activity.this)
                        .setTitle("提示")
                        .setMessage("fd 层 + maps 双重检测：\n\n"
                                + "① fd 扫描：遍历 /proc/self/fd，readlink 检查是否含 memfd:frida-agent\n"
                                + "② maps 搜索：解析 /proc/self/maps，搜索 frida/gadget/gum-js-loop 等关键词\n\n"
                                + "两路 OR 判定——任一检出即判定。\n\n"
                                + "绕过路线：\n"
                                + "  • hook readlinkat 返回假路径（如 /dev/null）\n"
                                + "  • hook opendir 过滤 frida 相关 fd\n"
                                + "  • 重命名 frida-agent 二进制\n\n"
                                + "静态复刻路线：\n"
                                + "  • IDA 分析 → 提取 SHA-256(SEED)\n"
                                + "  • SEED = 20280716\n"
                                + "  • 答案 = sha256(0x{SEED的4字节大端表示})\n\n"
                                + "注意诱饵 Fatdog_shade（少 w），真标记 Fatdog_shadow。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl22, 140));

        setContentView(root);
        ThemeKit.apply(this);
    }
}
