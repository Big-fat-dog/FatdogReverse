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
 * 扶桑树 KL28 雪落无痕：8 路评分阈值制 + 加载期检测（C++ OOP 实现）。
 * libsnow.so 导出十二个函数：
 *   int    nativeSignal()        — ① 信号试点自检
 *   int    nativePtrace()        — ② TracerPid 追踪
 *   int    nativeSmapsDirty()    — ③ 可执行段私有脏页
 *   int    nativeAnonExec()      — ④ 无名可执行映射（代码岛）
 *   int    nativeTrampoline()    — ⑤ ARM64 跳板扫描
 *   int    nativeLibcPrologue()  — ⑥ libc 入口 内存 vs 磁盘
 *   int    nativeLibcScan()      — ⑦ libc 段采样校验
 *   int    nativeLibcGot()       — ⑧ libc 符号解析完整性
 *   int    nativeLoadPhase()     — 加载期(.init_array)检测相位
 *   int    nativeFridaDetect()   — 综合检测（评分阈值制，≥2 判检出）
 *   String nativeAnswer()        — 最终答案（加载期命中则永久锁定）
 *   String nativeStatus()        — 检测详情
 *
 * 本关特色：C++ 面向对象重构——抽象基类 Probe + 8 个真身派生类各自实现一路检测，
 * 调用点只持基类指针做虚派发；signal handler 检查用 RAII 自动还原，不留副作用。
 */
public class j65Activity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(Ui.dp(16), Ui.dp(20), Ui.dp(16), Ui.dp(12));

        TextView tv = new TextView(this);
        tv.setText("KL28 · 雪落无痕（★★★★ 八路评分阈值制 · C++ OOP）\n\n"
                + "libsnow.so 导出十二个函数：\n"
                + "  int    nativeSignal()\n"
                + "  int    nativePtrace()\n"
                + "  int    nativeSmapsDirty()\n"
                + "  int    nativeAnonExec()\n"
                + "  int    nativeTrampoline()\n"
                + "  int    nativeLibcPrologue()\n"
                + "  int    nativeLibcScan()\n"
                + "  int    nativeLibcGot()\n"
                + "  int    nativeLoadPhase()\n"
                + "  int    nativeFridaDetect()\n"
                + "  String nativeAnswer()\n"
                + "  String nativeStatus()\n\n"
                + "评分阈值制（8 路命中 ≥2 才判检出）：\n"
                + "  ①② 进程级反调试：信号试点 / ptrace 追踪\n"
                + "  ③④⑤ 代码岛：脏页 / 无名可执行段 / ARM64 跳板\n"
                + "  ⑥⑦⑧ libc 完整性：入口比对 / 段采样 / 符号解析\n\n"
                + "★ 本关检测在 so【加载瞬间】(.init_array)就已执行并缓存，\n"
                + "  答案与加载期结果绑定——事后 hook 运行期检测解不开。\n\n"
                + "标记：两个标记一真一假，需仔细辨别");
        tv.setGravity(Gravity.CENTER);
        root.addView(tv, Ui.wrap(6));

        // 加载期相位：读这一行会触发 loadLibrary → .init_array 已跑完
        int phase = Wk28.nativeLoadPhase();
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
                int result = Wk28.nativeFridaDetect();
                if (result == 1) showFridaDetected();
                String status = Wk28.nativeStatus();
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
                if (ans.isEmpty()) { Toast.makeText(j65Activity.this, "请输入答案", Toast.LENGTH_SHORT).show(); return; }
                if (Wk28.nativeFridaDetect() == 1) { showFridaDetected(); return; }
                String expected = Wk28.nativeAnswer();
                if (ans.equals(expected)) {
                    Celebration.show(j65Activity.this, "FLAG_18_KL28{snow_leaves_no_trace}");
                    PassLog.mark(j65Activity.this, "KL28");
                } else {
                    Toast.makeText(j65Activity.this, "答案不对，再想想。", Toast.LENGTH_SHORT).show();
                }
            }
        });
        root.addView(subBtn, Ui.wrap(10));

        Button hint = new Button(this);
        hint.setText("提示"); Ui.styleButton(hint);
        hint.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                new AlertDialog.Builder(j65Activity.this)
                        .setTitle("提示")
                        .setMessage("八路评分阈值制（命中 ≥2 才判检出）：\n\n"
                                + "① 信号试点自检：SIGUSR1 是否被预装自定义 handler / 自触发是否通\n"
                                + "② TracerPid 追踪：/proc/self/status 的真实 tracer（pid 非 0）\n"
                                + "③ 可执行段私有脏页：file-backed 代码段被写脏（COW）\n"
                                + "④ 无名可执行映射：没有 VMA 名的 r-x 段 = 可疑代码岛\n"
                                + "⑤ ARM64 跳板扫描：代码岛里成簇的 LDR X16/17,[PC] + BR\n"
                                + "⑥ libc 入口比对：关键函数入口 内存 vs 磁盘 是否一致\n"
                                + "⑦ libc 段采样：代码段内部多点窗口 内存 vs 磁盘\n"
                                + "⑧ libc 符号解析：dlsym 结果是否仍归属 libc（抓换库/预加载）\n\n"
                                + "③~⑧ 是「抓注入本身」——洗掉特征串、hook 掉 libc 都躲不过；\n"
                                + "⑧ 更进一步：机器码一个字节没改，但只要实现被换掉就能抓到。\n\n"
                                + "★ 时机：检测在 so【加载瞬间】(.init_array)已跑完并缓存，\n"
                                + "  进关点按钮只是查看结果。因此 hook nativeFridaDetect 返回 0 没用；\n"
                                + "  要么干净环境直接提交，要么 spawn 抢在 so 加载前替换检测。\n\n"
                                + "实现为 C++ 面向对象：抽象基类 Probe + 虚派发，可尝试恢复 vtable。\n\n"
                                + "静态复刻：SEED = 20280722\n\n"
                                + "注意两个标记中有一个是诱饵，仔细对比拼写差异。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(hint, Ui.wrap(8));

        root.addView(Ui.banner(this, R.drawable.level_kl28, 140));

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
