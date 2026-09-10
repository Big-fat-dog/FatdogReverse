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
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * 扶桑树 KL25 暮雾锁听：三重检测 AND 判定。
 * libmist.so 导出六个函数：
 *   int    nativeMapsFrida()    — maps 特征搜索
 *   int    nativeThreadFinger() — 线程指纹检测
 *   int    nativeAuxvHook()     — auxv/ELF 一致性校验
 *   int    nativeFridaDetect()  — 综合检测（AND）
 *   String nativeAnswer()       — 最终答案
 *   String nativeStatus()       — 检测详情
 *
 * 关键点：AND 判定（Frida 指纹与运行时结构一致性全部成立）
 */
public class g62Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL25 · 暮雾锁听（★★★ AND 判定）\n\n"
                + "libmist.so 导出六个函数：\n"
                + "  int    nativeMapsFrida()\n"
                + "  int    nativeThreadFinger()\n"
                + "  int    nativeAuxvHook()\n"
                + "  int    nativeFridaDetect()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "AND 判定（条件全部成立才判定）：\n"
                + "  ① maps frida 特征\n"
                + "  ② 线程指纹检测\n"
                + "  ③ auxv/ELF 一致性校验\n\n"
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
                int result = Rk.nativeFridaDetect();
                String status = Rk.nativeStatus();
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
                if (ans.isEmpty()) { Toast.makeText(g62Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Rk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(g62Activity.this, "FLAG_18_KL25{mist_locks_the_ears}");
                    PassLog.mark(g62Activity.this, "KL25");
                } else {
                    Toast.makeText(g62Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(g62Activity.this)
                        .setTitle("提示")
                        .setMessage("三重 AND 判定：\n\n"
                                + "Frida 指纹命中且运行时结构一致才判定\n"
                                + "（与 OR 不同——需要全部条件同时成立）\n\n"
                                + "① maps frida 特征搜索\n"
                                + "② 线程指纹检测（gum-js-loop/gmain）\n"
                                + "③ auxv/ELF 一致性校验（ABI 无关）\n\n"
                                + "绕过路线：\n"
                                + "  • 只需让任一条结构校验失败即可\n"
                                + "  • 也可以只处理 Frida 特征路\n\n"
                                + "静态复刻：SEED = 20280719\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl25, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
