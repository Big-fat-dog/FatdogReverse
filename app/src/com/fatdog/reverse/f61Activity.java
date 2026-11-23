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
 * 扶桑树 KL24 冰鉴悬镜：进程运行时状态层 —— 反调试 / tracer 取证。
 * 4 路加权评分 + 加载期检测。
 * libice.so 导出八个函数：
 *   int    nativeTracerPid()        — /proc/self/status TracerPid（权重 2）
 *   int    nativeState()            — 进程状态字检查（权重 1）
 *   int    nativePpidChain()        — 父进程链调试器名（权重 2）
 *   int    nativeStatusIntegrity()  — status 结构完整性（权重 1）
 *   int    nativeLoadPhase()        — 加载期(.init_array)检测相位
 *   int    nativeFridaDetect()      — 综合检测（加权得分 ≥2 判检出）
 *   String nativeAnswer()           — 最终答案（加载期命中则永久锁定）
 *   String nativeStatus()           — 检测详情
 *
 * 与 KL21-23 的关键差异：
 *   ① 判定 = 加权评分（阈值 2）：ptrace 直证 / 调试器父进程各记 2 分，
 *      State / status 完整性各记 1 分 —— 真实 attach 即可触发，不再恒 0
 *   ② 时机 = so 加载瞬间(.init_array)先跑一次并缓存，进关点按钮会再算一次
 *
 * 本关检的是「调试器 / tracer」，不检 Frida 注入的内存痕迹（那是 KL25 起的考点）。
 */
public class f61Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL24 · 冰鉴悬镜（★★☆ 四路加权评分 · 反调试）\n\n"
                + "libice.so 导出八个函数：\n"
                + "  int    nativeTracerPid()\n"
                + "  int    nativeState()\n"
                + "  int    nativePpidChain()\n"
                + "  int    nativeStatusIntegrity()\n"
                + "  int    nativeLoadPhase()\n"
                + "  int    nativeFridaDetect()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "加权评分（阈值 ≥2 判检出）：\n"
                + "  ① TracerPid 非零 ········ 2 分（ptrace 直证）\n"
                + "  ② State 为 t/T ·········· 1 分（被 stop 的瞬间）\n"
                + "  ③ 父进程链含调试器名 ···· 2 分（调试器当爹）\n"
                + "  ④ status 结构被喂假 ···· 1 分（hook 痕迹）\n\n"
                + "★ 本关检测在 so【加载瞬间】(.init_array)先跑一次并缓存；\n"
                + "  进关点按钮会再算一次运行期状态——调试器挂上后点按钮即可见。\n\n"
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
                statusTv.setText("检测结果: " + (result == 1 ? "检出调试器/tracer" : "未检出") + "\n\n" + status);
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
                        .setMessage("进程运行时状态层 · 四路加权评分（反调试取证）：\n\n"
                                + "① TracerPid 非零 ········ 2 分\n"
                                + "   /proc/self/status 的 TracerPid 被内核写成 tracer 的 pid\n"
                                + "② State 为 t（traced stop）/ T（stopped） ··· 1 分\n"
                                + "③ 父进程链：PPid 的 cmdline 含 frida/gdb/lldb/gdbserver ··· 2 分\n"
                                + "④ status 缺 TracerPid/State 字段（被 hook 喂假） ··· 1 分\n\n"
                                + "加权得分 ≥2 判检出：任一直证（①或③）单独成立即可定罪，\n"
                                + "②④ 是辅助佐证，需两路合看。\n\n"
                                + "★ 时机：.init_array 里先跑一次并缓存；进关点按钮会再算一次运行期状态。\n"
                                + "  · 只启动 frida-server 不算——它是独立进程，本关不看它；\n"
                                + "  · Frida attach 注入完成后会 detach，TracerPid 随即归零，本关不追这个；\n"
                                + "  · 真正会触发的是「有个 tracer 一直挂着」：gdb / lldb / gdbserver attach、\n"
                                + "    或任何 ptrace 常驻的注入器。挂上后再点「运行检测」即可看到 ① 命中。\n\n"
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
                .setTitle("已被反调试检测")
                .setMessage("检测到调试器 / tracer 挂在本进程上！\n\n"
                        + "本关答案与检测结果绑定：加载期一旦命中，答案即被永久锁定；\n"
                        + "运行期命中则本次提交直接被拒。\n\n"
                        + "干净环境（没有 tracer 常驻）下直接计算并提交即可；"
                        + "若挂着 gdb/lldb/gdbserver，先 detach 再提交。")
                .setPositiveButton("知道了", null)
                .show();
    }
}
