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
 * 扶桑树 KL23 照妖显形：内存指纹三重校验（AND 判定）。
 * libsun.so 导出六个函数：
 *   int    nativeFridaDetect()  — 三路 AND（任一通过=安全）
 *   int    nativeMapsHex()      — maps hex 特征码
 *   int    nativeDtDebug()      — ELF DT_DEBUG
 *   int    nativeAuxv()         — /proc/self/auxv
 *   String nativeAnswer()       — 最终答案
 *   String nativeStatus()       — 检测详情
 *
 * 与 KL21/22 的关键差异：
 *   判定逻辑 = AND（全部检出才判定）vs OR（任一检出即判定）
 *   检测维度 = ELF 结构体解析（DT_DEBUG/auxv）vs 路径/字符串扫描
 */
public class e60Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL23 · 照妖显形（★★★ 三路 AND 判定）\n\n"
                + "libsun.so 导出六个函数：\n"
                + "  int    nativeFridaDetect()\n"
                + "  int    nativeMapsHex()\n"
                + "  int    nativeDtDebug()\n"
                + "  int    nativeAuxv()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "三路 AND 判定（任一通过=安全）：\n"
                + "  ① maps hex：r-xp 段搜索 frida 特征字节\n"
                + "  ② DT_DEBUG：ELF 头 PT_DYNAMIC 段检查\n"
                + "  ③ auxv：/proc/self/auxv AT_PHDR 篡改检测\n\n"
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
                int result = Ok.nativeFridaDetect();
                String status = Ok.nativeStatus();
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
                if (ans.isEmpty()) { Toast.makeText(e60Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Ok.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(e60Activity.this, "FLAG_18_KL23{mirror_shows_true_face}");
                    PassLog.mark(e60Activity.this, "KL23");
                } else {
                    Toast.makeText(e60Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(e60Activity.this)
                        .setTitle("提示")
                        .setMessage("三重内存指纹 + AND 判定：\n\n"
                                + "① maps hex：在 r-xp 可执行段中搜索 frida 特征字节\n"
                                + "② DT_DEBUG：解析 ELF PT_DYNAMIC 段，检查 DT_DEBUG 值\n"
                                + "③ auxv：读 /proc/self/auxv，检查 AT_PHDR 是否异常\n\n"
                                + "AND 判定：三路全部检出才判定 Frida 存在\n"
                                + "（与 KL21/22 的 OR 判定相反——任一通过即安全）\n\n"
                                + "绕过路线：\n"
                                + "  • 只需绕过三路中的任一路即可\n"
                                + "  • hook maps 解析 / hook ELF 读取 / hook auxv\n"
                                + "  • Frida spawn 模式可避免部分检测\n\n"
                                + "静态复刻：SEED = 20280717\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl23, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
