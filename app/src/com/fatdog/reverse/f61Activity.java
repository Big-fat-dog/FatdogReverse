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
 * 扶桑树 KL24 冰鉴悬镜：进程状态双重校验（OR 判定）。
 * libice.so 导出五个函数：
 *   int    nativeTracerPid()     — /proc/self/status TracerPid
 *   int    nativeState()         — 进程状态字检查
 *   int    nativeFridaDetect()   — 综合检测（OR）
 *   String nativeAnswer()        — 最终答案
 *   String nativeStatus()        — 检测详情
 *
 * 与 KL21-23 的关键差异：
 *   检测目标 = 进程运行时状态（status/state）vs 内存/端口/ELF 结构
 *   判定逻辑 = OR（与 KL21/22 相同，与 KL23 AND 相反）
 */
public class f61Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL24 · 冰鉴悬镜（★☆☆ 双重状态检测）\n\n"
                + "libice.so 导出五个函数：\n"
                + "  int    nativeTracerPid()\n"
                + "  int    nativeState()\n"
                + "  int    nativeFridaDetect()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "双重 OR 判定（任一检出即判定）：\n"
                + "  ① TracerPid：/proc/self/status 值非零\n"
                + "  ② State：进程状态为 t/T（被停止）\n\n"
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
                int result = Qk.nativeFridaDetect();
                String status = Qk.nativeStatus();
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
                if (ans.isEmpty()) { Toast.makeText(f61Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                String expected = Qk.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(f61Activity.this, "FLAG_18_KL24{ice_mirror_catches_all}");
                    PassLog.mark(f61Activity.this, "KL24");
                } else {
                    Toast.makeText(f61Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(f61Activity.this)
                        .setTitle("提示")
                        .setMessage("进程状态双重校验：\n\n"
                                + "① TracerPid：/proc/self/status 中 TracerPid 非零\n"
                                + "② State：进程状态为 t（traced stop）或 T（stopped）\n\n"
                                + "OR 判定：任一检出即判定 Frida 存在\n"
                                + "（与 KL23 AND 相反——任一检出即判定）\n\n"
                                + "绕过路线：\n"
                                + "  • 挂钩 /proc/self/status 读取\n"
                                + "  • 挂钩 fopen/fgets 拦截 status 文件\n"
                                + "  • 直接修改 TracerPid 值\n\n"
                                + "静态复刻：SEED = 20280718\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl24, 140));

        setContentView(Ui.wrapScroll(root));
        ThemeKit.apply(this);
    }
}
