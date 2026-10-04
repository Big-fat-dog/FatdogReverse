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
 * 扶桑树 KL24 冰鉴悬镜：进程状态层 4 路评分阈值制 + 加载期检测。
 * libice.so 导出八个函数：
 *   int    nativeTracerPid()        — /proc/self/status TracerPid
 *   int    nativeState()            — 进程状态字检查
 *   int    nativePpidChain()        — 父进程链调试器名
 *   int    nativeStatusIntegrity()  — status 结构完整性
 *   int    nativeLoadPhase()        — 加载期(.init_array)检测相位
 *   int    nativeFridaDetect()      — 综合检测（评分阈值制，≥2 判检出）
 *   String nativeAnswer()           — 最终答案（加载期命中则永久锁定）
 *   String nativeStatus()           — 检测详情
 *
 * 与 KL21-23 的关键差异：
 *   ① 判定 = 评分阈值制（4 路信号命中 ≥2），不再单点 OR 定罪
 *   ② 时机 = so 加载瞬间(.init_array)就已跑完检测并缓存，进关点按钮只是「看结果」
 */
public class f61Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL24 · 冰鉴悬镜（★★☆ 四路评分阈值制）\n\n"
                + "libice.so 导出八个函数：\n"
                + "  int    nativeTracerPid()\n"
                + "  int    nativeState()\n"
                + "  int    nativePpidChain()\n"
                + "  int    nativeStatusIntegrity()\n"
                + "  int    nativeLoadPhase()\n"
                + "  int    nativeFridaDetect()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "评分阈值制（4 路命中 ≥2 才判检出）：\n"
                + "  ① TracerPid 非零\n"
                + "  ② State 为 t/T\n"
                + "  ③ 父进程链含调试器名\n"
                + "  ④ status 结构被喂假\n\n"
                + "★ 本关检测在 so【加载瞬间】(.init_array)就已执行并缓存，\n"
                + "  答案与加载期结果绑定——事后 hook 运行期检测解不开。\n\n"
                + "标记：两个标记一真一假，需仔细辨别");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        // 加载期相位：读这一行会触发 loadLibrary → .init_array 已跑完
        int phase = Qk.nativeLoadPhase();
        final TextView statusTv = new TextView(this);
        statusTv.setText("加载期检测(.init_array)：相位 " + phaseDesc(phase)
                + "（检测在 so 加载那一刻就已完成）\n\n点击「运行检测」查看完整状态");
        statusTv.setTextColor(phase == 2 ? 0xFFFF6B6B : Color.LTGRAY);
        statusTv.setTypeface(Typeface.MONOSPACE);
        statusTv.setTextSize(12);
        statusTv.setGravity(Gravity.CENTER);
        root.addView(statusTv, Ui.fullWidth(6));

        Button runBtn = new Button(this);
        runBtn.setText("运行检测"); Ui.styleButton(runBtn);
        runBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                int result = Qk.nativeFridaDetect();
                if (result == 1) showFridaDetected();
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
                if (Qk.nativeFridaDetect() == 1) { showFridaDetected(); return; }
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
                        .setMessage("进程状态层 · 四路评分阈值制：\n\n"
                                + "① TracerPid：/proc/self/status 中 TracerPid 非零\n"
                                + "② State：进程状态为 t（traced stop）或 T（stopped）\n"
                                + "③ 父进程链：PPid 的 cmdline 含 frida/gdb/lldb/gdbserver\n"
                                + "④ status 结构完整性：status 缺关键字段（被 hook 喂假）\n\n"
                                + "评分阈值制：命中 ≥2 路才判检出（单点信号不误杀）\n\n"
                                + "★ 时机是本关重点：检测在 so【加载瞬间】(.init_array)已跑完并缓存，\n"
                                + "  进关点按钮只是查看结果。因此：\n"
                                + "  • hook nativeFridaDetect 返回 0 没用——答案读的是内部缓存；\n"
                                + "  • 想通关要么「根本别让它检出」（干净环境直接提交），\n"
                                + "    要么用 spawn 抢在 so 加载前，把 .init_array 里的检测函数替掉。\n\n"
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

    private static String phaseDesc(int phase) {
        switch (phase) {
            case 2:  return "已命中(2)";
            case 1:  return "干净(1)";
            default: return "未执行(0)";
        }
    }

    private void showFridaDetected() {
        new AlertDialog.Builder(this)
                .setTitle("已被 Frida 检测")
                .setMessage("检测到 Frida 注入！\n\n本关答案与【加载期】检测结果绑定：\n"
                        + "一旦 so 加载时被检出，答案即被永久锁定，事后 hook 运行期检测也解不开。\n\n"
                        + "干净环境下直接计算并提交即可；若确需挂 Frida，须用 spawn 抢在 so 加载前处理 .init_array 中的检测。")
                .setPositiveButton("知道了", null)
                .show();
    }
}
